"""Autoencoder trained on benign flows; high reconstruction error marks a flow as unusual."""

from __future__ import annotations

import numpy as np
import torch
from torch import nn

from aegis.config import AutoencoderConfig


def _layers(sizes: list[int]) -> list[nn.Module]:
    layers: list[nn.Module] = []
    for size_in, size_out in zip(sizes, sizes[1:]):
        layers += [nn.Linear(size_in, size_out), nn.ReLU()]
    return layers[:-1]  # The final layer stays linear.


class AutoencoderScorer:
    def __init__(self, config: AutoencoderConfig, seed: int) -> None:
        self.config = config
        self.seed = seed
        self.model: nn.Module | None = None

    def fit(self, benign_train: np.ndarray, benign_val: np.ndarray) -> "AutoencoderScorer":
        cfg = self.config
        torch.manual_seed(self.seed)
        generator = np.random.default_rng(self.seed)
        sizes = [benign_train.shape[1], *cfg.hidden, cfg.latent]
        self.model = nn.Sequential(*_layers(sizes), nn.ReLU(), *_layers(sizes[::-1])).to(cfg.device)
        optimizer = torch.optim.Adam(self.model.parameters(), lr=cfg.learning_rate)
        data = torch.as_tensor(benign_train, dtype=torch.float32)

        best_loss, best_state, stale = float("inf"), None, 0
        for _ in range(cfg.epochs):
            self.model.train()
            order = generator.permutation(len(data))
            for start in range(0, len(data), cfg.batch_size):
                batch = data[order[start : start + cfg.batch_size]].to(cfg.device)
                optimizer.zero_grad()
                nn.functional.mse_loss(self.model(batch), batch).backward()
                optimizer.step()

            val_loss = float(self.reconstruction_error(benign_val).mean())
            if val_loss < best_loss - 1e-6:
                best_loss, stale = val_loss, 0
                best_state = {k: v.detach().clone() for k, v in self.model.state_dict().items()}
            else:
                stale += 1
                if stale >= cfg.patience:
                    break
        if best_state is None:
            raise RuntimeError("Autoencoder training did not produce a finite validation loss")
        self.model.load_state_dict(best_state)
        return self

    @torch.no_grad()
    def reconstruction_error(self, X: np.ndarray) -> np.ndarray:
        if self.model is None:
            raise RuntimeError("Call fit before scoring")
        self.model.eval()
        errors = []
        data = torch.as_tensor(X, dtype=torch.float32)
        for start in range(0, len(data), 8192):
            batch = data[start : start + 8192].to(self.config.device)
            errors.append(((self.model(batch) - batch) ** 2).mean(dim=1).cpu().numpy())
        return np.concatenate(errors)
