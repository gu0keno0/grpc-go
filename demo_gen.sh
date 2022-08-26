mkdir ~/tmp
go build -o ~/tmp/xds_grpc_demo_client examples/features/xds/client/main.go
go build -o ~/tmp/grpc_demo_server examples/helloworld/greeter_server/main.go
go build -o ~/tmp/grpc_demo_client examples/helloworld/greeter_client/main.go

# Run Server:
# ~/tmp/grpc_demo_server -port 34567 -message 'hello from server1 '
# ~/tmp/grpc_demo_server -port 34567 -message 'hello from server2 '

# Run Client:
# export GRPC_XDS_BOOTSTRAP=/home/jefjiang/workplace/indis-configs/grpc-xds-bootstrap.json
# export GRPC_GO_LOG_VERBOSITY_LEVEL=99 ; export GRPC_GO_LOG_SEVERITY_LEVEL=info
#     With Sidecar:
#          ~/tmp/grpc_demo_client -addr localhost:18081 -service grpc-demo-service-1.envoy.prod:18081  -name servicemesh-101
#          ~/tmp/grpc_demo_client -addr localhost:18081 -service grpc-demo-service-2.envoy.prod:18081  -name servicemesh-101
#     Without Sidecar:
#          ~/tmp/xds_grpc_demo_client -name "istio mesh world B" -target xds:///grpc-demo-service-1.prod.linkedin.com:18080
#          ~/tmp/xds_grpc_demo_client -name "istio mesh world B" -target xds:///grpc-demo-service-2.prod.linkedin.com:18080
