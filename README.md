# 🛠️ Instalador Premium Seguro de Odoo (v16.0 – v19.0)

**Autor:** [Samuel Sarante](https://github.com/)  
**Fecha:** 02/10/2025  
**Compatibilidad:** Ubuntu 22.04 / 24.04 LTS  
**Licencia:** MIT  

---

## 📖 Descripción general

Este script automatiza **la instalación completa, segura y optimizada de Odoo en entornos de producción**, compatible con las versiones **16.0 a 19.0**.  
Incluye configuraciones avanzadas de seguridad, rendimiento, backups automáticos, monitoreo antivirus y soporte para certificados SSL (Let’s Encrypt o autofirmados).

Ideal para entornos empresariales o implementaciones en servidores en la nube (VPS, bare-metal o dedicados).

---

## 🚀 Características principales

- 🔒 **Seguridad mejorada**
  - Configura **UFW (firewall)** y **Fail2Ban** automáticamente.
  - Instalación opcional de **ClamAV** con escaneo programado cada 5 horas.
  - Contraseña **superadmin aleatoria** (opcional).

- ⚙️ **Automatización total**
  - Crea usuario del sistema exclusivo para Odoo.
  - Configura PostgreSQL y entorno virtual Python (venv).
  - Descarga e instala dependencias desde un archivo `install.txt`.
  - Instala `wkhtmltopdf` compatible con Ubuntu 24.04.

- 🌐 **Nginx + SSL**
  - Configura proxy inverso con Nginx.
  - Soporte automático para **certificados Let’s Encrypt** o **autofirmados**.
  - Redirección automática de HTTP → HTTPS.

- 🗂️ **Backups automáticos**
  - Copias diarias comprimidas de la base de datos PostgreSQL.
  - Retención configurable (por defecto: 30 días).

- 🌍 **GeoLite2 integrado**
  - Descarga las bases de datos ASN, City y Country para geolocalización de IPs.

- ⚡ **Rendimiento optimizado**
  - Calcula dinámicamente los parámetros `workers`, `memory limits` y `threads` según CPU/RAM detectada.

---

## 📋 Requisitos previos

Antes de ejecutar el script, asegúrate de:

1. Ejecutarlo en una **instalación limpia de Ubuntu 22.04 o 24.04 LTS**.
2. Tener permisos de **root** (`sudo su` o ejecutar con `sudo`).
3. Disponer de conexión a Internet estable.

---

## 🧩 Archivos requeridos

| Archivo | Descripción |
|----------|--------------|
| `install.sh` | Script principal de instalación (este archivo). |
| `install.txt` | Lista de paquetes del sistema a instalar (usado por apt). |

Ejemplo de `install.txt`:

```bash
git
python3
python3-venv
python3-pip
postgresql
nginx
ufw
fail2ban
curl
npm
