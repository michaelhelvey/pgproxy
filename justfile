run *args:
    go run . {{args}}

build:
    go build .

clean:
    rm ./pgproxy

test:
    go test -v ./...

e2e:
    cd ./test && source ./venv/bin/activate && python -m unittest
