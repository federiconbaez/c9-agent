# c9-agent: diseño

## 1. Propósito

Ejecutar trabajos 3D (Blender `bpy` headless, Unreal Python vía Remote Execution, renders) en la estación Linux propia **sin** depender de una aplicación de escritorio abierta, con un perímetro mínimo: el agente solo hace lo que está en una allowlist cerrada y solo cuando el trabajo trae una firma SSH válida de una clave autorizada.

## 2. Arquitectura

```
emisor (laptop / bot)                         estación (usuario dedicado c9-agent)
  sign_job ── ssh-keygen -Y sign ──►  cola  ──►  c9-agent (systemd --user)
  (clave sk-ed25519 en YubiKey)    incoming/      1. claim (rename atómico)
                                                   2. verify: firma → formato → vigencia → nonce
                                                   3. allowlist.plan → argv fijo
                                                   4. runner: sin shell, env mínimo, timeout, rlimits
  ◄──────── results/<id>.result.json + .sig ◄──    5. resultado firmado (ssh-keygen -Y sign)
```

- **Cola pluggable.** v0.1 implementa `DirQueue` (directorio local; puede ser un clon de un repo git privado sincronizado con `git pull`/`git push` por un timer aparte). Backend HTTP en el droplet: misma interfaz (`pending`, `claim`, `finish`, `write_result`), pendiente.
- **Firmas.** `ssh-keygen -Y` con namespaces separados: `c9-agent-job` para trabajos, `c9-agent-result` para resultados. El principal se deduce con `find-principals` contra `allowed_signers`; el JSON del trabajo no puede declarar quién lo firmó. Compatible con `sk-ssh-ed25519@openssh.com` (YubiKey, toque obligatorio).
- **Formato del trabajo** (campos exactos, cualquier extra se rechaza):
  `{"version":1,"id","nonce","issued_at","expires_at","action","args"}`.
- **Anti-replay.** `expires_at` obligatorio, vigencia máx. 24 h, tolerancia de reloj 120 s, nonce de un solo uso guardado con `O_CREAT|O_EXCL`. El nonce se consume solo después de validar firma y formato, así un atacante sin clave no puede "quemar" nonces. Los nonces vencidos se podan.

## 3. Allowlist

| Acción | Argumentos | argv |
|---|---|---|
| `ping` | — | `true` |
| `blender_script` | `blend` (rel. a `projects_root`, `.blend`), `script` (rel. a `scripts_root`, `.py`) | `blender --background --factory-startup --disable-autoexec <blend> --python <script> -- --output-dir <out>` |
| `blender_render` | `blend`, `frame_start`, `frame_end` (≤1000 frames), `engine` ∈ {CYCLES, EEVEE Next, Workbench} | `blender --background ... --render-anim` |
| `unreal_python` | `script` (rel. a `scripts_root`) | `c9-unreal-exec --script <s> --output-dir <out>` |

Reglas: argumentos con claves exactas y tipos estrictos (sin `bool` como entero); rutas con regex, sin `..`, `.`, vacíos ni absolutas, resueltas con `resolve(strict=True)` y comprobadas contra la raíz (bloquea symlinks hacia afuera); los scripts solo salen de `scripts_root` (revisado por Federico, solo lectura para el agente). No existe ninguna acción de shell libre ni evaluación de expresiones.

## 4. Ejecución

- `subprocess.Popen(argv, shell=False)`, `stdin=/dev/null`, entorno reducido a `PATH`, `LC_ALL`, `HOME=<out>` (no hereda tokens).
- Nueva sesión + `RLIMIT_NOFILE`, `RLIMIT_CORE=0`, `RLIMIT_FSIZE`; timeout por acción con `killpg` de todo el grupo.
- Logs: cola de 256 KiB de stdout/stderr dentro del resultado.
- Unidad systemd `--user` con `ProtectHome=tmpfs`, `ProtectSystem=strict`, `NoNewPrivileges`, rutas escribibles solo cola/salida, `MemoryMax`, `TasksMax`, `CPUQuota`. Nota: en servicios de usuario parte del sandboxing depende de user namespaces sin privilegios; verificar con `systemd-analyze --user security c9-agent`.

## 5. Modelo de amenazas

| Amenaza | Mitigación |
|---|---|
| **Inyección de prompts** en un bot (contenido web, issue, mail) que intenta crear trabajos | El bot no tiene la clave privada (vive en la YubiKey de Federico, con toque). Un trabajo escrito por un bot comprometido llega sin firma válida y se rechaza antes de parsear acciones. Una inyección puede, como mucho, generar un trabajo que Federico ve y se niega a firmar. |
| Robo del trabajo firmado y reenvío | Nonce de un solo uso + vencimiento. |
| Modificar un trabajo firmado | La firma cubre los bytes exactos; cualquier cambio invalida. |
| Firma de otro contexto (p. ej. commit git) reutilizada | Namespace obligatorio `c9-agent-job`. |
| Escritura en la cola por terceros | Sin firma = rechazado; archivos symlink en `incoming/` se ignoran. |
| Path traversal / symlinks | §3. |
| Inyección de argumentos (`-o...`, `;`, `$()`) | Regex de rutas sin `-` inicial, argv como lista, sin shell. |
| `.blend` malicioso con scripts embebidos | `--disable-autoexec` + `--factory-startup`; el agente corre como usuario sin acceso a `/home/fbaez`. Riesgo residual: bugs del parser de Blender → aislamiento por usuario + systemd. |
| Script de Unreal arbitrario | Solo desde `scripts_root`, que el agente no puede escribir. |
| Agotamiento de recursos | Timeouts, rlimits, límites de cgroup, máx. 1000 frames. |
| Resultados falsificados | Resultados firmados con la clave del agente (`c9-agent-result`); el emisor verifica con la pública. |
| Compromiso de la clave del emisor | Clave sk con toque; rotación editando `allowed_signers`; `valid-before` opcional por principal. |

Fuera de alcance v0.1: aislamiento fuerte (contenedor/VM), cifrado de la cola, backend HTTP.

## 6. Integración opcional con c9mem

Si `c9mem_bin` está configurado y existe, se emite `c9mem event-append c9agent.start|end --task <id>`. Si falla, no bloquea la ejecución.

## 7. Pendiente

- Cliente `c9-unreal-exec` (protocolo Remote Execution de Unreal: descubrimiento multicast UDP 239.0.0.1:6766 + comando por TCP), restringido a `127.0.0.1`.
- Backend HTTP para el droplet y sincronizador git.
- Verificación de resultados del lado del emisor (`verify_result`).
