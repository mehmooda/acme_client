package main

import "fmt"

func LogE(args ...interface{}) {
	if *LOGLEVEL > 0 {
		fmt.Printf("E: ")
		fmt.Println(args...)
	}
}

func LogV(args ...interface{}) {
	if *LOGLEVEL > 1 {
		fmt.Printf("V: ")
		fmt.Println(args...)
	}
}

func LogN(args ...interface{}) {
	if *LOGLEVEL > 2 {
		fmt.Printf("N: ")
		fmt.Println(args...)
	}
}
