# PyBorg Web Interface

This directory contains the optional web interface for PyBorg.

## Features

- **Games**: HTML5 Breakout and Mars Colony games
- **Admin Panel**: Bot management and monitoring (requires authentication)
- **API Endpoints**: RESTful APIs for bot data
- **Leaderboards**: Game statistics and rankings

## Setup

The web interface is optional and requires a web server (Apache, Nginx, or development server).

### Development Server

```bash
# Simple PHP development server
cd web
php -S localhost:8080

# Python development server (for static files)
python3 -m http.server 8080
```

### Production Setup

1. Copy files to your web server document root
2. Configure your web server to serve the files
3. Ensure PHP is enabled (for API endpoints)
4. Set appropriate file permissions

### Configuration

- Update `config.php` with your database paths
- Configure authentication in `admin_panel.php`
- Adjust API endpoints as needed

## Security Notes

- The admin panel should be password protected
- Database files should not be web accessible
- Consider using HTTPS for production
- Regularly update dependencies