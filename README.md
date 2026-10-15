# Anillo de honeypots con Moving Target Defense (MTD)

Caso de estudio de **lista circular doblemente enlazada** (Estructuras de Datos), aplicado a ciberseguridad.
Implementado en **Python** (solo librería estándar) con un **frontend web** que dibuja el anillo en tiempo real.

## Descripción

Un conjunto de servidores señuelo (honeypots) forma un anillo. **Solo uno está expuesto a la red** y la exposición rota de forma continua. Así, la información que un atacante obtiene en el reconocimiento queda obsoleta. Si el servidor expuesto recibe un ataque, la rotación es inmediata, y los servidores que acumulan demasiados ataques pasan a cuarentena.

## Contexto: Moving Target Defense

MTD es una estrategia de defensa proactiva: en vez de proteger un sistema estático, cambia periódicamente la superficie de ataque. En red, las técnicas más comunes son el salto de IP, el salto de puertos y la migración de servicios entre máquinas virtuales. Un esquema habitual usa un intervalo de rotación largo por defecto y rota de inmediato cuando se sospecha un ataque, que es justamente la política que implementa este caso. Los honeypots estáticos son fáciles de identificar, y rotar cuál está expuesto ayuda a resolver ese problema.

## Reglas del sistema

1. Cada `intervalo_ms` (30 s por defecto) la exposición pasa al siguiente servidor del anillo.
2. Si atacan al servidor expuesto, la rotación es **inmediata**.
3. Un servidor que acumula `umbral_ataques` (3 por defecto) se **aísla** en cuarentena y la rotación lo salta.
4. Terminada la cuarentena (`cuarentena_ms`, 60 s por defecto) el servidor vuelve al anillo.
5. Se puede **retroceder** al servidor anterior (rollback) si una rotación causó problemas.
6. Un servidor comprometido de forma definitiva se **retira** del anillo en O(1).

## ¿Por qué una lista circular doblemente enlazada?

| Característica | Qué resuelve |
|---|---|
| **Circular** | La rotación nunca termina: después del último viene el primero, sin `None` que manejar. |
| **Doble** (`prev`) | Permite el rollback hacia atrás y retirar un nodo conocido en O(1) enlazando sus vecinos. |
| **Nodo como referencia** | Con un `dict` id → nodo, aislar y retirar no necesitan recorrer la lista. |

Con un arreglo habría que reindexar al retirar y usar módulo en cada movimiento.

## Estructura del proyecto

```
lista_circular_doble.py   # estructura genérica (Nodo + ListaCircularDoble)
anillo_mtd.py             # lógica del dominio: estados, rotación, ataques, cuarentena
servidor.py               # servidor HTTP (stdlib): API JSON + sirve el frontend
index.html                # frontend: anillo en SVG, controles y historial
test_anillo.py            # pruebas unitarias (unittest)
```

## Cómo ejecutar

Requiere Python 3.9 o superior. No hay dependencias que instalar.

```bash
python servidor.py
# abrir http://localhost:8000
```

Pruebas:

```bash
python -m unittest -v
```

## Frontend

- Anillo dibujado en SVG: flecha clara = `next`, flecha oscura = `prev`.
- Colores: **rojo** expuesto, **verde** en espera, **gris punteado** aislado (con cuenta regresiva de cuarentena).
- Clic en un servidor para seleccionarlo y luego **Atacar**, **Aislar** o **Retirar**.
- Botones **Rotar →** y **← Retroceder**, **+10 s** / **+30 s** y modo **Auto**.
- **Agregar honeypot** y **Reiniciar**, más el historial de los últimos servidores expuestos.

El reloj es **simulado** (lo controla el servidor), así que la demo es reproducible y no depende del tiempo real.

## Estados de un servidor

| Estado | Significado | Transición |
|---|---|---|
| `EXPUESTO` | Es el único visible a la red | → `EN_ESPERA` al rotar; → `AISLADO` al superar el umbral |
| `EN_ESPERA` | En el anillo, listo para ser expuesto | → `EXPUESTO` cuando le toca |
| `AISLADO` | En cuarentena, la rotación lo salta | → `EN_ESPERA` al terminar la cuarentena |

## Operaciones y complejidad

| Operación | Costo | Nota |
|---|---|---|
| `agregar` | O(1) | Inserta al final (`head.prev`) |
| `rotar` | O(1) típico, O(n) peor caso | Peor caso: salta muchos aislados |
| `registrar_ataque` | O(1) + rotación | Rota solo si el atacado es el expuesto |
| `aislar` | O(1) + rotación | El nodo se queda en el anillo |
| `retirar` | O(1) | `eliminar(nodo)` sin buscar |
| `tick` | O(n) | Revisa cuarentenas; con un min-heap bajaría a O(log n) por evento |

## API REST

| Método | Ruta | Cuerpo | Efecto |
|---|---|---|---|
| GET | `/api/estado` | — | Foto del anillo |
| POST | `/api/tiempo` | `{"ms": 10000}` | Avanza el reloj y ejecuta `tick` |
| POST | `/api/rotar` | `{"sentido": 1}` o `-1` | Rota adelante o atrás |
| POST | `/api/atacar` | `{"id": "HP-1"}` | Registra un ataque |
| POST | `/api/aislar` | `{"id": "HP-1"}` | Cuarentena inmediata |
| POST | `/api/retirar` | `{"id": "HP-1"}` | Retiro permanente |
| POST | `/api/agregar` | — | Agrega un honeypot |
| POST | `/api/reiniciar` | — | Reinicia la simulación |

Los errores responden `400` con `{"error": "..."}`.

## Decisiones de diseño

- **Aislar vs. retirar:** aislar es temporal y el nodo permanece en el anillo; retirar es permanente y el nodo sale.
- **Ancla de la rotación (`_expuesto`):** puede quedar apuntando a un nodo aislado y es intencional, porque la rotación necesita una referencia desde donde buscar.
- **Tope `size` al buscar candidato:** evita el ciclo infinito típico de las listas circulares cuando todos los nodos están aislados.
- **Tiempo como parámetro (`ahora`):** la lógica no usa el reloj del sistema, por lo que es determinista y se prueba sin esperas.
- **Un solo `tick` por llamada:** aunque pase más de un intervalo, solo se hace una rotación.

## Casos borde cubiertos por las pruebas

Lista vacía, un solo nodo (se apunta a sí mismo), eliminar head, medio y único nodo, ciclo completo de rotación, ataque al expuesto, umbral de aislamiento, fin de cuarentena, todos los nodos aislados (sin ciclo infinito y con recuperación), rollback con vuelta por el extremo, retirar el expuesto, retirar al único y volver a agregar, id duplicado e id inexistente.

## Otras estructuras de datos aplicables a MTD

La lista circular resuelve **quién está expuesto**. Otros problemas de MTD piden otra estructura:

| Problema | Estructura | Por qué |
|---|---|---|
| Mapear IP real a IP virtual | Tabla hash (`dict`) en ambos sentidos | Traducción O(1) por paquete |
| Elegir IPs o puertos nuevos sin repetir | Conjunto de libres + cola FIFO de expiración | Tomar uno es O(1); con TTL fijo caducan en orden |
| Programar el próximo salto de cada host | Min-heap por timestamp | Extraer el próximo evento en O(log n) |
| Mutación de topología y rutas | Grafo (lista de adyacencia) | Rutas alternativas con BFS o Dijkstra |
| Lista negra de clientes | Conjunto hash (IPs) y trie (rangos CIDR) | Pertenencia O(1) o por prefijo |
| Detectar escaneo para disparar la rotación | Buffer circular con ventana | Memoria acotada, solo analiza lo reciente |
| Historial para deshacer configuraciones | Pila | LIFO natural para rollback múltiple |

## Limitaciones

- Es una **simulación** de la lógica de planificación: no cambia IPs ni puertos reales. Para eso haría falta SDN o reglas de firewall.
- El intervalo fijo es **predecible**: hay trabajo que muestra que un atacante con IA puede inferir cuándo se dispara una rotación de IP. Una mejora sencilla es sumar un jitter aleatorio al intervalo.
- Cada rotación tiene un costo en recursos, por lo que rotar más seguido no siempre es mejor.

## Posibles extensiones

1. Jitter aleatorio en el intervalo de rotación.
2. Salto de puerto además de la rotación de servidor.
3. Min-heap para programar rotaciones por servidor con intervalos distintos.
4. Persistir el historial de ataques y usarlo para calibrar el umbral.

## Referencias

- Patente, *Moving target defense systems and methods*: https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/11902320
- *A Cost-effective Shuffling Method against DDoS Attacks using Moving Target Defense*: https://arxiv.org/pdf/1903.10102
- *Using a Combination of Shuffling and Diversity Moving Target Defense Techniques*: https://distantreader.org/stacks/journals/etasr/etasr-4417.pdf
- *Random Host and Service Multiplexing for MTD in SDN* (ICC 2019): https://utoronto.academia.edu/DilliSharma
- *MTDSense: AI-Based Fingerprinting of MTD Techniques in SDN*: https://arxiv.org/html/2408.03758v1
- *Risk-Based & Honeypot-Informed MTD* (póster, University of Waterloo): https://uwaterloo.ca/cybersecurity-privacy-institute/sites/default/files/uploads/documents/poster-30.pdf
- *Dynamic Honeypot Deployment in SDN*: https://journal.uod.ac/index.php/uodjournal/article/download/3367/1916/
- *A Survey of Moving Target Defenses for Network Security*: https://arxiv.org/pdf/1905.00964
