#!/bin/sh

# Conexion manual a SMB versiñin 1, en Bash Shell 1.0.x
# Si conecta, se confirma que es SMBv1 !!! 
# (r) hackingyseguridad.com 2026
# @antonio_taboada

# SMBv1 comando
smbclient -L //$1/ -m NT1
