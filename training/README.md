# Model training

Create the CPU-only Python environment and train the bootstrap model with:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-training.txt
.\.venv\Scripts\python.exe training\train_model.py
```

For captured and labeled windows, pass `--input path\to\windows.csv`. The CSV must contain these columns in one row per **completed 1-second window**:

```csv
packet_rate,mean_packet_bytes,syn_ratio,udp_ratio,label,group_id
12.0,64.0,1.0,0.0,0,session-a
31.0,118.0,0.0,1.0,0,session-a
```

`packet_rate` is the number of counted packets divided by the configured window duration. `mean_packet_bytes` is the mean total IP packet length. Runtime counts public inbound UDP packets and TCP SYN packets without ACK, grouped by remote/protocol/local-port. For those separate buckets the ratio pair is fixed: TCP SYN `(syn_ratio=1, udp_ratio=0)`; UDP `(syn_ratio=0, udp_ratio=1)`. Other TCP traffic is outside the current model's packet scope. Labels are `0` benign and `1` attack. `group_id` is an arbitrary pseudonymous capture/session identifier; rows from one group are kept on one side of the grouped train/test split. Do not place IP addresses or other personal data in this field.

The requested personal-PC scenario is live YouTube broadcasting through OBS plus coding on a low-to-medium connection. Outbound broadcast packets and video frames are not features and are not processed. The synthetic benign scenarios approximate only counted inbound UDP/QUIC/application traffic and selected SYN windows; they are assumptions, not measured observations.

Capture adapters must aggregate the same tuple and only emit completed windows; do not convert bidirectional whole-flow statistics into these columns. Keep raw captures and labels outside the repository. The exporter stores only the input basename, feature order, group counts, and aggregate metrics. Retraining from a CSV is labeled `local-capture-unvalidated`; output remains advisory and the generated C header keeps `ADOS_MODEL_ENFORCE_ALLOWED` set to `0`. A domain owner must separately review representative captures, false-positive behavior, and deployment results before any enforcement policy is enabled.

`models/model.json` records source, split, tool versions, and held-out metrics. The initial checked-in model is explicitly a synthetic bootstrap trained to exercise the pipeline; its metrics describe generated scenarios only.
