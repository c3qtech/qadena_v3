package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	qadenacommon "qadena_v3/x/qadena/common"
	"qadena_v3/x/qadena/types"
)

var signer []byte

const (
	defaultName = "world"
)

var (
	addr      = flag.String("addr", "localhost:50051", "the address to connect to")
	name      = flag.String("name", defaultName, "Name to greet")
	signerArg = flag.String("s", "", "signer ID")
)

var SupportsUnixDomainSockets bool = true

func main() {
	flag.Parse()

	var conn *grpc.ClientConn
	var err error

	if SupportsUnixDomainSockets {
		// connect using unix domain socket
		conn, err = grpc.Dial("unix:///tmp/qadena_50051.sock", grpc.WithInsecure())
	} else {
		conn, err = grpc.Dial(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	// connect using unix domain socket
	// conn, err := grpc.Dial("unix:///tmp/qadena.sock", grpc.WithInsecure())

	if err != nil {
		fmt.Println("did not connect:", err)
		return
	}
	defer conn.Close()
	c := types.NewGreeterClient(conn)

	// Contact the server and print out its response.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := c.SayHello(ctx, &types.HelloRequest{Name: *name})
	if err != nil {
		fmt.Println("could not greet:", err)
		return
	}
	fmt.Println("Greeting:", r.GetMessage())

	enclaveClient := types.NewQadenaEnclaveClient(conn)

	r2, err := enclaveClient.SyncWallets(ctx, &types.MsgSyncWallets{})
	if err != nil {
		fmt.Println("could not sync wallets", err)
		return
	}
	fmt.Println("syncwallets", qadenacommon.PrettyPrint(r2))
}
