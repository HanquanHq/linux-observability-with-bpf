package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	fmt.Println("start listening 80 port")
	log.Fatalf("%v", http.ListenAndServe(":80", nil))
}

// go build -o capabilities main.go
// ./capabilities // permission denied

//  capsh --caps='cap_net_bind_service+eip cap_setpcap,cap_setuid,cap_setgid+ep' --keep=1 --user="nobody" --addamb=cap_net_bind_service -- -c "./capabilities"