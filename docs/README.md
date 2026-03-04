# Policy Engine

Powered by

[![UoSLOGO](./images/UniSouthampton.png)](https://dips.soton.ac.uk/#home)

## **General Description**

The Policy Engine provides a suite of functionality to inspect, process and use ODRL policies.

## **Main Goal/Functionalities**

Currently the following main functionalities are supported: 

* Visualising an ODRL policy to inspect it
* Validating the correctness of an ODRL policy file against the specification
* Evaluating one or more ODRL policies against a State of the World (like an event log, or a data access request)
* Generating synthetic ODRL policies, and generating synthetic States of the World about policies to be used for testing purposes.

## **Commercial Information**


| Organisation (s) | License Nature | License |
| --- | --- | --- |
| University of Southampton  | Open Source | MIT Licence |


## **How To Install**

### Requirements

Python, rdflib, pyshacl, pandas

### Detailed Steps

Currently the Policy Engine can be inported as a Python library to use its main functions. The code for the core functions of the Policy Engine can be found in the `PolicyEngineLibrary` subfolder.



## Expected KPIs

| What | How | Values |
| --- | --- | --- |
| 1) Support Policy Comparison 2) Support different policy evaluation semantics (see paper) and complex language features (such as obligations, duties, remedies, consequence) 3) Data Usage Policy Evaluation Scalability 4) Policy Comparison Scalability | 1) fully fledged comparison of policies, supporting all common ODRL features (85% of features, see KPI for policy editor) 2) experiments comparing different semantics and features  3) and 4) experiments with synthetic data: policies and states of the world | 1) at least two semantics and two complex features 2) support of ODRL 2.2 (ODRL Lite and Full ODRL) and main semantics from Jaime et al. Evaluation and Comparison Semantics for ODRL, 2025  3) and 4) support >20  policies of average size (>5 rules per policy), evaluated over states of the world from different users   |

Progress towards KPIs:
* 04/03/2026: 1) Implemented "refinements" and "constraints" on policy comparison engine 2) the engine currently supports ODRL lite semantics with permissions and prohibitions 3) and 4) we developed synthetic policy and state of the world generation capability
