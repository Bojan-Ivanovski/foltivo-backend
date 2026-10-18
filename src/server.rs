//! HTTP/1 transport deadlines matching the former net/http server policy.
use crate::auth::{Error, Result};
use axum::{body::Body, extract::ConnectInfo, Router};
use hyper::{body::Incoming, service::service_fn};
use hyper_util::rt::TokioIo;
use std::{
    future::Future,
    io,
    net::SocketAddr,
    pin::Pin,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::{Instant, Sleep},
};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

const HEADER: u8 = 0;
const BODY: u8 = 1;
const IDLE: u8 = 2;
fn read_duration(phase: u8) -> Duration {
    Duration::from_secs(match phase {
        IDLE => 60,
        BODY => 10,
        _ => 5,
    })
}
struct DeadlineIo {
    socket: TcpStream,
    phase: Arc<AtomicU8>,
    observed: u8,
    read: Pin<Box<Sleep>>,
    write: Option<Pin<Box<Sleep>>>,
}
impl DeadlineIo {
    fn new(socket: TcpStream, phase: Arc<AtomicU8>) -> Self {
        Self {
            socket,
            phase,
            observed: HEADER,
            read: Box::pin(tokio::time::sleep(read_duration(HEADER))),
            write: None,
        }
    }
}
impl AsyncRead for DeadlineIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let phase = this.phase.load(Ordering::Acquire);
        if phase != this.observed {
            this.observed = phase;
            this.read
                .as_mut()
                .reset(Instant::now() + read_duration(phase));
        }
        let before = buffer.filled().len();
        match Pin::new(&mut this.socket).poll_read(cx, buffer) {
            Poll::Ready(result) => {
                if result.is_ok() && buffer.filled().len() > before && phase == IDLE {
                    this.phase.store(HEADER, Ordering::Release);
                    this.observed = HEADER;
                    this.read
                        .as_mut()
                        .reset(Instant::now() + read_duration(HEADER));
                }
                Poll::Ready(result)
            }
            Poll::Pending => {
                if this.read.as_mut().poll(cx).is_ready() {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "HTTP read deadline exceeded",
                    )))
                } else {
                    Poll::Pending
                }
            }
        }
    }
}
impl AsyncWrite for DeadlineIo {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.write.is_none() {
            this.write = Some(Box::pin(tokio::time::sleep(Duration::from_secs(10))));
        }
        match Pin::new(&mut this.socket).poll_write(cx, buffer) {
            Poll::Ready(result) => {
                this.write = None;
                Poll::Ready(result)
            }
            Poll::Pending => {
                if this
                    .write
                    .as_mut()
                    .is_some_and(|s| s.as_mut().poll(cx).is_ready())
                {
                    Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "HTTP write deadline exceeded",
                    )))
                } else {
                    Poll::Pending
                }
            }
        }
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().socket).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().socket).poll_shutdown(cx)
    }
}
pub async fn serve(listener: TcpListener, app: Router, stop: CancellationToken) -> Result<()> {
    let mut connections = JoinSet::new();
    let mut result = Ok(());
    loop {
        tokio::select! {
            _=stop.cancelled()=>{tracing::info!("api_shutdown_started");break},
            incoming=listener.accept()=>{match incoming{Ok((socket,address))=>{let app=app.clone();let stop=stop.clone();connections.spawn(async move{connection(socket,address,app,stop).await;});},Err(_)=>{result=Err(Error::validation("HTTP server failed to listen"));break}}},
            Some(_)=connections.join_next(),if !connections.is_empty()=>{}
        }
    }
    stop.cancel();
    let drained = tokio::time::timeout(Duration::from_secs(10), async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        connections.abort_all();
        return Err(Error::validation("HTTP server graceful shutdown timed out"));
    }
    result
}
async fn connection(socket: TcpStream, address: SocketAddr, app: Router, stop: CancellationToken) {
    let phase = Arc::new(AtomicU8::new(HEADER));
    let io = TokioIo::new(DeadlineIo::new(socket, phase.clone()));
    let service = service_fn(move |mut request: hyper::Request<Incoming>| {
        let app = app.clone();
        let phase = phase.clone();
        request.extensions_mut().insert(ConnectInfo(address));
        phase.store(BODY, Ordering::Release);
        async move {
            let result = app.oneshot(request.map(Body::new)).await;
            phase.store(IDLE, Ordering::Release);
            result
        }
    });
    let builder = hyper::server::conn::http1::Builder::new();
    let connection = builder.serve_connection(io, service);
    tokio::pin!(connection);
    tokio::select! {_=&mut connection=>{},_=stop.cancelled()=>{connection.as_mut().graceful_shutdown();let _=tokio::time::timeout(Duration::from_secs(10),&mut connection).await;}}
}
