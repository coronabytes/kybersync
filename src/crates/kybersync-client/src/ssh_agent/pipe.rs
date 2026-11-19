//! The OpenSSH agent named pipe, as Windows' own `ssh-agent` service serves it.

use super::{AgentSession, KeyStore};
use ssh_agent_lib::agent::{NamedPipeListener, listen};
use std::sync::Arc;
use tokio::runtime::Handle;
use tokio::task::JoinHandle;

/// Where Windows OpenSSH (`ssh.exe`, `ssh-add.exe`) looks for the agent.
pub const OPENSSH_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";

/// Serve `store` on `pipe` until the task is aborted. Fails when the pipe
/// already exists, usually because Windows' "OpenSSH Authentication Agent"
/// service is running.
pub fn serve(rt: &Handle, pipe: &str, store: Arc<KeyStore>) -> Result<JoinHandle<()>, String> {
    let listener = {
        let _in_rt = rt.enter();
        // `first_pipe_instance`: never share a pipe name another process owns.
        // Retried briefly: right after the agent was turned off and on, the
        // aborted listener may not have closed its pipe yet.
        let mut tries = 0;
        let bound = loop {
            match NamedPipeListener::bind(pipe) {
                Err(e) if e.raw_os_error() == Some(5) && tries < 5 => {
                    tries += 1;
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                r => break r,
            }
        };
        bound.map_err(|e| {
            if e.raw_os_error() == Some(5) || e.raw_os_error() == Some(231) {
                format!(
                    "{pipe} is in use. Stop and disable the \"OpenSSH Authentication Agent\" \
                     Windows service (or quit the other SSH agent), then turn this on again."
                )
            } else {
                format!("opening {pipe}: {e}")
            }
        })?
    };
    tracing::info!(pipe, "ssh-agent: listening");
    let pipe = pipe.to_string();
    Ok(rt.spawn(async move {
        if let Err(e) = listen(listener, AgentSession(store)).await {
            tracing::error!(pipe, "ssh-agent: the pipe stopped: {e:?}");
        }
    }))
}
