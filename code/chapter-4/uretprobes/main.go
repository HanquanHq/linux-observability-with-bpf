package main

import (
	"fmt"
)

type Programmer struct {
	Weight int
}

func (p Programmer) GetWeight(plus int) int {
	return p.Weight + plus
}

func main() {
	p := Programmer{666}
	fmt.Println(p.GetWeight(1))
	fmt.Println(p.GetWeight(2))
	fmt.Println(p.GetWeight(3))
}

// go build -gcflags '-N -l' -o hello-bpf main.go && nm hello-bpf > log.txt
