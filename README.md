# SOME/IP Radio Service Example

This setup provides a Docker-based environment with a SOME/IP radio service and a radio client.

## Quick Start

1.  Build and start the environment:
    ```bash
    docker-compose build
    docker-compose up -d server
    docker-compose run client
    ```

2.  You will be in the client terminal. Use the following keys to control the radio:
    -   `+`: Increase volume
    -   `-`: Decrease volume
    -   `SPACE`: Change station
    -   `ESC`: Turn on/off
    -   `Q`: Quit

## Structure

-   `server/`: Dockerfile and configuration for the radio service.
-   `client/`: Dockerfile and configuration for the radio client.
-   `src/`: Common source code for both components.
-   `docker-compose.yml`: Orchestrates the containers with a dedicated network (172.20.0.0/24).
-   `Dockerfile.combined`: Multi-stage Dockerfile for efficient building.
