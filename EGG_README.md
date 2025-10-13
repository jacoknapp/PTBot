# PTBot Pterodactyl Egg

This is a Pterodactyl egg for deploying [PTBot](https://github.com/jacoknapp/ptbot), a Discord bot for managing Pterodactyl game servers.

## Installation

1. Import the `egg-ptbot.json` file into your Pterodactyl panel as a new egg
2. Create a new server using this egg
3. Configure the required environment variables:
   - `DISCORD_TOKEN`: Your Discord bot token
   - `PTERO_BASE_URL`: Your Pterodactyl panel URL
   - `PTERO_CLIENT_TOKEN`: Pterodactyl API token

## Features

- Automatic installation script that creates the data directory and config.json
- Environment variable configuration for all PTBot settings
- Proper startup detection based on the "Logged in" message
- Support for all PTBot configuration options

## Configuration

The egg supports all PTBot configuration options through environment variables:

- **DISCORD_TOKEN**: Discord bot token (required)
- **PTERO_BASE_URL**: Pterodactyl panel URL (required)
- **PTERO_CLIENT_TOKEN**: Pterodactyl API token (required)
- **ALERT_CHANNEL_ID**: Discord channel for alerts (optional)
- **HEALTH_CHECK_INTERVAL**: Health check frequency (default: 2m)
- **ALLOWED_GUILD_IDS**: Comma-separated guild IDs (optional)
- **ALLOWED_ROLE_IDS**: Comma-separated role IDs (optional)
- **ALLOWED_USER_IDS**: Comma-separated user IDs (optional)
- **PTBOT_INSECURE**: Allow insecure TLS (default: false)

## Usage

After installation, the bot will automatically start and connect to Discord. Users can then use slash commands like `/pt list`, `/pt status`, `/pt start`, etc. to manage servers.

For more information about PTBot features and commands, see the [PTBot README](https://github.com/jacoknapp/ptbot).