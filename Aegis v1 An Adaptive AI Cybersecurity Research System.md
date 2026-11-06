# Aegis v1: An Adaptive AI Cybersecurity Research System

Nov 7, 2026 · @Melchior Remilien

## Research vision

Aegis asks whether an AI defender can learn from competition, anticipate an adaptive attacker, and defend better against previously unseen threats, rather than only recognizing attacks it has already seen. Two learning agents, a red-team attacker and a blue-team defender, interact in controlled simulations; a generative model produces diverse synthetic malicious traffic; and opponent modeling lets each agent predict the other.

Traditional intrusion detection relies on collected datasets and known signatures, and performance can degrade when attackers change technique. Aegis combines three research directions and evaluates them independently and together:

1. **Generative intelligence:** realistic, diverse synthetic malicious traffic and scenarios.
2. **Adversarial intelligence:** attacker and defender trained through competition and self-play.
3. **Opponent intelligence:** agents that predict the strategies and behavioral changes of their opponents.

## System architecture

Aegis has five interconnected components.

| Component | Role | Key points |
| --- | --- | --- |
| A. Generative | Synthetic attack generation with a conditional GAN | Traffic conditioned on attack category; variations of known patterns; eventually conditioned on defender weaknesses. Samples must be checked for statistical realism, feature consistency and validity. The discriminator is not the defender. |
| B. Adversarial | Red attacker and blue defender trained with RL (PPO explored) | Attacker selects strategies and adapts when detected; defender detects, responds and controls false alarms. Training against a pool of historical opponents reduces instability. |
| C. Opponent | Behavioral prediction | Defender predicts the attacker's next strategy and detects behavior changes; attacker anticipates the defender's response. Compared as: no modeling, defender models attacker, both model each other. |
| D. Simulation | Existing environments, not a new simulator | CybORG, NASim, CyberBattleSim through a common Aegis interface with separate adapters; one primary environment, the others for external validation. |
| E. Evaluation | Measures improvement rather than competition alone | Detection, reliability, attack effectiveness, adaptability, prediction, robustness, generalization, efficiency. |

Generator, in simplified form:

```latex
x_{synthetic} = G(z, c)
```

where z is random noise, c is a condition such as an attack category, and G is the generator.

Opponent models, with h\_t the observable interaction history:

```latex
M_D(a_A \mid h_t) \qquad M_A(a_D \mid h_t) \qquad \pi_D(a \mid o_t, M_D)
```

The first two are each agent's model of the other's likely action; the third is the defender's policy using both its observation and its model of the attacker.

Evaluation metrics by area:

| Area | Metrics |
| --- | --- |
| Detection | Precision, recall, F1-score |
| Reliability | False-positive and false-negative rates |
| Attack effectiveness | Attack success rate |
| Adaptability | Performance against changing strategies |
| Prediction | Next-action and strategy prediction accuracy |
| Robustness | Performance against unseen attacks |
| Generalization | Performance across different environments |
| Efficiency | Detection and response time |

## Research problem, questions and hypotheses

Central problem: how can generative modeling, adversarial multi-agent learning and opponent modeling be combined to build cybersecurity agents that anticipate and adapt to evolving attack strategies, and is the resulting defender more robust and adaptive than a conventional machine-learning intrusion detection system?

The hypotheses are to be investigated, not assumed.

| ID | Research question | Hypothesis |
| --- | --- | --- |
| 1 | Can generative models produce realistic, diverse and useful synthetic training scenarios? | H1: Carefully validated synthetic attack data can improve detection on sufficiently different test scenarios. |
| 2 | Does adversarial self-play improve the adaptability of attacker and defender agents? | H2: Adversarial competition improves adaptability against changing attack strategies. |
| 3 | Can opponent modeling help agents predict the strategies and behavioral changes of other learning agents? | H3: Opponent modeling improves prediction of an adversary's next actions. |
| 4 | Does mutual opponent modeling improve defensive performance over a defender that does not model its opponent? | H4: A defender using opponent predictions outperforms an otherwise comparable defender without them. |
| 5 | Do improvements transfer to unseen scenarios and other simulation environments? | H5: Combining generation, adversarial learning and opponent modeling improves robustness against unseen simulated attacks. |

## Experimental methodology

Each component is developed and evaluated independently before all are trained together.

| Experiment | What it does | Compares |
| --- | --- | --- |
| 1. Baseline intrusion detection | Conventional ML on labeled datasets (CICIDS2017, UNSW-NB15) using Logistic Regression, Random Forest and an MLP | Establishes performance without generative augmentation or adaptive agents |
| 2. Generative attack scenarios | Conditional generative model for synthetic malicious traffic | Original data; original plus synthetic; synthetic under different conditions |
| 3. Adversarial self-play | Red and blue agents in a simulation | Defender trained against fixed attacks vs against an adaptive attacker |
| 4. Opponent modeling | Behavioral prediction in the agents | No modeling; defender models attacker; both model each other |
| 5. Combined Aegis | Integrates all three with ablations | Configurations A-F below |

Ablation design for Experiment 5:

| Configuration | Generator | Self-play | Opponent modeling |
| --- | --- | --- | --- |
| A: Baseline | No | No | No |
| B: Generative | Yes | No | No |
| C: Adversarial | No | Yes | No |
| D: Opponent-aware | No | Yes | Yes |
| E: Hybrid | Yes | Yes | No |
| F: Full Aegis | Yes | Yes | Yes |

The ablation tests whether the complete system provides measurable gains over simpler configurations.

## Technical stack

A manageable Python-based research environment; libraries are added only as each component needs them.

| Component | Technologies |
| --- | --- |
| Programming | Python |
| Machine learning | PyTorch, scikit-learn |
| Generative modeling | PyTorch |
| Reinforcement learning | Gymnasium, Stable-Baselines3 |
| Data processing | Pandas, NumPy |
| Visualization | Matplotlib |
| Simulation | CybORG, NASim, CyberBattleSim |
| Experiment tracking | CSV, SQLite initially |
| Version control | Git, GitHub |

## Development roadmap

The vision is ambitious, so implementation is incremental across five phases.

| Phase | Work | Deliverable |
| --- | --- | --- |
| 1. Research foundation and environment setup | Study existing simulators; select the primary environment; understand its observations, actions and rewards; establish a common agent interface | A working cybersecurity simulation and baseline agent |
| 2. Baseline detection and generative modeling | Explore CICIDS2017 and UNSW-NB15; build and evaluate conventional detectors; implement a conditional generative model; validate generated traffic before training use | Baseline detector and evaluated synthetic traffic generator |
| 3. Adversarial agents | Develop attacker and defender; introduce RL (PPO); repeated competition; historical opponent pools | Two agents learning through simulated competition |
| 4. Opponent modeling | Record interaction histories; train models to predict opponent actions and strategies; use predictions in decisions; evaluate adaptation when an opponent changes behavior | Opponent-aware attacker and defender agents |
| 5. Integration and evaluation | Combine all components; run ablations; test on unseen attacks; add environments; analyze robustness and generalization | An experimentally evaluated Aegis research prototype |

## Contribution, scope and final definition

**Intended contribution:** an examination of whether generative modeling, adversarial multi-agent reinforcement learning and opponent modeling complement one another, and under what conditions they improve cybersecurity defense. Potential contributions:

1. A modular framework integrating generative traffic creation, adversarial agents and opponent modeling.
2. An evaluation of whether opponent-aware defenders outperform conventional and self-play-only defenders.
3. An investigation of how synthetic scenarios affect robustness and generalization.
4. An evaluation of agent performance across different simulation environments.

Novelty must be established through a literature review; combining three known techniques is not automatically novel.

**Scope and safety:** adaptive attackers run only inside controlled simulations; synthetic traffic is generated and validated offline or in isolated environments; no attack agent targets public networks or unauthorized systems; real-world validation, if any, happens only in explicitly authorized environments. The goal is to study adaptive defense, not to build an unrestricted autonomous hacking system.

**Project objective:** investigate whether generative modeling, adversarial multi-agent learning and mutual opponent modeling enable cybersecurity agents to anticipate evolving attack strategies and develop more robust defensive policies.

**Central question:** can an AI defender learn not only to recognize malicious activity, but also to anticipate the behavioral changes of an adaptive adversary?

**Long-term vision:** a framework in which attackers and defenders learn from simulated competition, use generative models to explore new scenarios, and predict one another's strategies.

**Recommendation recorded in v1:** keep this as the complete vision but build a smaller first prototype: one simulator, one conventional detection baseline and a basic synthetic data generator, then add adversarial learning and opponent modeling progressively. The next step is a literature-backed proposal showing what exists and where Aegis could contribute.
