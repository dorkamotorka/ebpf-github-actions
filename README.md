# Running eBPF in GitHub Actions
 
Demo repository for running eBPF in GitHub Actions. It includes:

- `/app` directory, where you can find eBPF related code - A simple `execve()` syscall tracer.
- `Dockerfile` for building container`with eBPF code
- `.github/workflows/run.yaml` GitHub action that will run the container with eBPF code.

It is simply to prove how eBPF can be run in GitHub Actions and export some useful data. 

In this demo, it traces all the `execve()` syscalls and captures the output and saves it to an artifact to view it later.

For proper products this data would be exported to some third-party external endpoint - but this would be beyond this demo.
