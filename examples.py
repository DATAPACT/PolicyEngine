# Define the SPARQL query to find matching nodes
sparql_query = """
PREFIX odrl: <http://www.w3.org/ns/odrl/2/>
PREFIX dpv: <https://w3id.org/dpv/owl#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
SELECT ?action ?assignee ?target_source ?purpose
WHERE {
  ?node odrl:action ?action ;
        odrl:assignee ?assignee ;
        odrl:target ?target ;
        odrl:constraint ?constraint .
        ?constraint odrl:leftOperand odrl:purpose ;
                    odrl:operator odrl:eq ;
                    odrl:rightOperand ?purpose .
        ?target odrl:source ?target_source.
}
"""

example_permission_policy = {
    "permission": [
        {
            "action": "http://www.w3.org/ns/odrl/2/appendTo",
            "assignee": "https://w3id.org/dpv/owl#Citizen",
            "target": "http://example.org/datasets/climateChangeData",
            "constraint": [
                {
                    "leftOperand": "http://www.w3.org/ns/odrl/2/purpose",
                    "operator": "http://www.w3.org/ns/odrl/2/eq",
                    "rightOperand": "https://w3id.org/dpv/owl#Personalisation"
                }
            ]
        }
    ],
    "uid": "http://example.org/policy-79f7e6ba-daff-4919-940f-a1ad1344a97b",
    "@context": "http://www.w3.org/ns/odrl.jsonld",
    "@type": "http://www.w3.org/ns/odrl/2/Policy"
}

example_prohibition_policy = {
    "prohibition": [
        {
            "action": "http://www.w3.org/ns/odrl/2/appendTo",
            "assignee": "https://w3id.org/dpv/owl#Citizen",
            "target": "http://example.org/datasets/climateChangeData",
            "constraint": [
                {
                    "leftOperand": "purpose",
                    "operator": "http://www.w3.org/ns/odrl/2/eq",
                    "rightOperand": "https://w3id.org/dpv/owl#Personalisation"
                }
            ]
        }
    ],
    "uid": "http://example.org/policy-79f7e6ba-daff-4919-940f-a1ad1344a97a",
    "@context": "http://www.w3.org/ns/odrl.jsonld",
    "@type": "http://www.w3.org/ns/odrl/2/Policy"
}


# Example data
example_data = [
    {
        "rule": None,
        "actor": None,
        "action": None,
        "target": None,
        "purpose": None,
        "query": "",
        "constraints": [
            {
                "type": None,
                "operator": None,
                "value": ""
            }
        ],
        "actorrefinements": [
            {
                "type": None,
                "operator": None,
                "value": ""
            }
        ],
        "actionrefinements": [
            {
                "type": None,
                "operator": None,
                "value": ""
            }
        ],
        "purposerefinements": [
            {
                "type": None,
                "operator": None,
                "value": ""
            }
        ],
        "targetrefinements": [
            {
                "type": None,
                "operator": None,
                "value": ""
            }
        ]
    },
    {
        "rule": "http://www.w3.org/ns/odrl/2/Permission",
        "actor": "https://w3id.org/dpv/owl#JobApplicant",
        "action": "http://www.w3.org/ns/odrl/2/archive",
        "target": "http://example.org/datasets/economicIndicators",
        "purpose": "https://w3id.org/dpv/owl#HumanResourceManagement",
        "query": "",
        "constraints": [
            {
                "type": "http://www.w3.org/ns/odrl/2/absolutePosition",
                "operator": "http://www.w3.org/ns/odrl/2/eq",
                "value": "10"
            },
            {
                "type": "http://www.w3.org/ns/odrl/2/count",
                "operator": "http://www.w3.org/ns/odrl/2/eq",
                "value": "5"
            }
        ],
        "actorrefinements": [
            {
                "type": "https://w3id.org/dpv/owl#actorEnhancedProperty",
                "operator": None,
                "value": ""
            },
            {
                "type": "https://w3id.org/dpv/owl#actorEnhancedProperty",
                "operator": "http://www.w3.org/ns/odrl/2/eq",
                "value": "1"
            }
        ],
        "actionrefinements": [
            {
                "type": "https://w3id.org/dpv/owl#actionEnhancedProperty",
                "operator": None,
                "value": ""
            }
        ],
        "purposerefinements": [
            {
                "type": "https://w3id.org/dpv/owl#purposeEnhancedProperty",
                "operator": None,
                "value": ""
            }
        ],
        "targetrefinements": [
            {
                "type": "http://example.org/datasets/title",
                "operator": None,
                "value": "Economic Indicators Data"
            }
        ]
    }
]