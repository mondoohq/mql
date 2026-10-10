# OPC UA Resource Pack

```coffeescript
# gather all available namespaces 
opcua.namespaces { * }
opcua.namespaces: [
  0: {
    id: 0
    name: "http://opcfoundation.org/UA/"
  }
  1: {
    id: 1
    name: "urn:open62541.server.application"
  }
]

# gather root node
mql> opcua.root
opcua.root: opcua.node id="i=84" name="Root"


# gather all nodes
mql> opcua.nodes { name namespace.name }

# gather node with a specific id
mql> opcua.nodes.where (id == "i=2253")
opcua.nodes.where: [
  0: opcua.node id="i=2253" name="Server"
]

# gather details about the server
mql> opcua.server { * }
opcua.server: {
  buildInfo: {
    BuildDate: "2023-05-21T21:03:43.817369Z"
    BuildNumber: "May 20 2023 15:51:32"
    ManufacturerName: "open62541"
    ProductName: "open62541 OPC UA Server"
    ProductURI: "https://open62541.org"
    SoftwareVersion: "1.3.5-994-g5d73f0cc5"
  }
  node: opcua.node id="i=2253" name="Server"
  currentTime: 2023-05-22 08:28:30.625932 +0000 UTC
  state: "ServerStateRunning"
  startTime: 2023-05-21 21:03:43.834304 +0000 UTC
}
```

## Example Servers

*Open62541*

The [Open62541](https://github.com/open62541/open62541) includes may examples for building an Open62541 server.


*Azure IoT Edge*

Azure has an example for [OPC PLC server](https://github.com/Azure-Samples/iot-edge-opc-plc) available that you can quickly start locally:

```bash
# run service with no security configuration
docker run --rm -it -p 50000:50000 -p 8080:8080 --name opcplc mcr.microsoft.com/iotedge/opc-plc:latest --pn=50000 --autoaccept --sph --sn=5 --sr=10 --st=uint --fn=5 --fr=1 --ft=uint --gn=5 --ut --dca
```

## UI

*Simple OPC-UA GUI client*

This is a very simple [client](https://github.com/FreeOpcUa/opcua-client-gui) that allows you to browse the OPC UA data:

```bash
pip3 install opcua-client
opcua-client
```