package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

func main() {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the path of the .exe file: ")
	exePath, err := reader.ReadString('\n')
	if err != nil {
		log.Fatalf("Failed to read input: %v", err)
	}
	exePath = strings.TrimSpace(exePath)
	pE := strings.ReplaceAll(exePath, `\`, `\\`)
	a := 3
	psCommand := fmt.Sprintf(".\\donut.exe -a %d -o main.bin -i \"%s\" -b 1 -k 2 -x 3", a, pE)
	c := exec.Command("powershell.exe", psCommand)
	fmt.Printf("Executing: %s\n", c.String())
	c.Stderr = os.Stderr
	err = c.Run()
	if err != nil {
		log.Fatalf("Failed to execute PowerShell command: %v", err)
	}
}
