# c9-agent

Agente liviano para ejecutar trabajos 3D (Blender `bpy` headless, Unreal Python Remote Execution, renders) en una estación Linux propia, a partir de una cola de trabajos JSON **firmados con `ssh-keygen -Y`** (compatible con YubiKey `sk-ed25519`).

- Allowlist cerrada de acciones con argumentos validados; sin shell libre.
- Anti-replay (nonce de un uso + vencimiento).
- Ejecución con entorno mínimo, timeouts y límites; resultados firmados.
- Servicio `systemd --user` bajo un usuario dedicado.

Diseño y modelo de amenazas: [`DISENO.md`](DISENO.md).

## Uso rápido

```bash
# emisor: firmar y encolar
python -m c9agent.sign_job --key ~/.ssh/id_ed25519_sk --action blender_render \
  --args '{"blend":"demo/escena.blend","frame_start":1,"frame_end":24}' --out /srv/c9-agent/queue/incoming

# estación: procesar
python -m c9agent --config ~/.config/c9-agent/config.toml --once
```

Ejemplos de configuración en `examples/` y unidad en `contrib/systemd/`.

## Tests

```bash
python -m pytest -q
```

## Licencia

MIT. Ver `LICENSE`.
