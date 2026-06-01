package main

import (
    "net/http"
    "os/exec"
)

func HandleLogin(w http.ResponseWriter, r *http.Request) {
    r.ParseForm()
    username := r.FormValue("username")
    cmd := exec.Command("echo", username)
    cmd.Run()
}

func main() {
    http.HandleFunc("/login", HandleLogin)
    http.ListenAndServe(":8080", nil)
}
