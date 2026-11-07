"""CICIDS2017 benign rows that may be mislabeled attack replies. No label is changed here.

These are the cleaned benign rows sent from the victim 192.168.10.50 to the attacker 172.16.0.1,
99.1% of them from port 80. The reasoning is an inference from capture context: on the raw rows,
97.6% have the same 5-tuple reversed as an attack flow that day and 99.96% fall inside that day's
attack window. The features the models use have no IP columns, so the rows are listed by their
position in the cleaned dataset, built from the TrafficLabelling release of the same flows.
"""

from __future__ import annotations

import base64
import hashlib
import zlib

import numpy as np

from aegis.data.dataset import BENIGN, Dataset

# Cleaned CICIDS2017 row count with Destination Port dropped, which these positions depend on.
CLEANED_ROWS = 2199163
EXPECTED_ROWS = 38045
_CHECK_COLUMNS = ['Flow Duration', 'Total Fwd Packets', 'Init_Win_bytes_forward', 'Init_Win_bytes_backward']
_CHECK_DIGEST = "94b4da6bb327bc0a6640437532b400e2d24533373b1a86750610981ac775945a"
_POSITION_GAPS = (
    "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"
)


def suspect_benign_mask(ds: Dataset) -> np.ndarray | None:
    """Mark the suspect rows, or return None for data these positions do not describe."""
    if ds.name != "cicids2017" or len(ds.X) != CLEANED_ROWS:
        return None
    gaps = np.frombuffer(zlib.decompress(base64.b64decode(_POSITION_GAPS)), dtype="<u4")
    positions = np.cumsum(gaps.astype(np.int64))
    values = ds.X.iloc[positions][_CHECK_COLUMNS].to_numpy(np.float32).tobytes()
    if len(positions) != EXPECTED_ROWS or np.any(ds.family[positions].astype(str) != BENIGN):
        raise ValueError("The suspect benign positions do not point at benign rows in this data")
    if hashlib.sha256(values).hexdigest() != _CHECK_DIGEST:
        raise ValueError("The suspect benign positions do not match this CICIDS2017 copy")
    mask = np.zeros(len(ds.X), dtype=bool)
    mask[positions] = True
    return mask
