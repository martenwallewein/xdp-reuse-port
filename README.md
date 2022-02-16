# xdp_reuse_port example

## Run as docker container
Build:
`docker build . -t xdp_reuse_port:latest`

Load BPF:
`docker run --privileged --net=host xdp_reuse_port:latest -iface wlan0`
