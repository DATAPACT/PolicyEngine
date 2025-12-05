# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------------
# DISCLAIMER: This software is provided "as is" without any warranty,
# express or implied, including but not limited to the warranties of
# merchantability, fitness for a particular purpose, and non-infringement.
#
# In no event shall the authors or copyright holders be liable for any
# claim, damages, or other liability, whether in an action of contract,
# tort, or otherwise, arising from, out of, or in connection with the
# software or the use or other dealings in the software.
# -----------------------------------------------------------------------------
import os
import time
import uuid
from telnetlib import EC

from owlready2 import owl, default_world
from rdflib import Graph, Namespace

def use_case_ontology_classes(ontology_file):
    """Returns the list of classes from the ontology
    :param ontology_file: ontology file
    :type ontology_file: str
    :return: list of classes
    :rtype: list
    Example:
            {
          "Exercise": [
            "CleanAndJerk",
            "Crunch",
            "Deadlift",
            "ImaginaryChair",
            "MachineRow",
            "PushUp",
            "RussianTwist",
            "SplitSquats",
            "Squat",
            "Weightlifting"
          ],
          "DifficultyLevel": [
            "Easy",
            "Hard",
            "Medium"
          ],
          "ExerciseTypes": [
            "AgilityAndPlyometric",
            "Balance",
            "Cardiovascular",
            "CoreTraining",
            "Endurance",
            "Flexibility",
            "FunctionalTraining",
            "HighIntensityIntervalTraining",
            "Isolation",
            "Rehabilitation",
            "Strength"
          ],
          "MuscleGroup": [
            "Abdominals",
            "Abs",
            "Arms",
            "Chest",
            "Legs",
            "Shoulders"
          ]
        }
    """
    thing_subclass = {}
    read_ontology(ontology_file)
    for cls in list(owl.Thing.subclasses()):
        subitems = [
            prettyfy(str(item), False)
            for item in list(cls.subclasses())
            if (len(list(cls.subclasses())) > 0)
        ]
        thing_subclass[prettyfy(str(cls), False)] = subitems
    return thing_subclass


def read_ontology(ontology_file, world=None):
    """Reads the ontology file and returns the ontology
    :param ontology_file: ontology file
    :type ontology_file: str
    :param world: world
    :type world: owlready2.World
    :return: ontology
    :rtype: owlready2.Ontology
    """
    ontology_file = str(os.path.relpath(ontology_file))
    if world is not None:
        ontology = world.get_ontology(
            os.path.join(settings.MEDIA_ROOT, str(ontology_file))
        ).load()
        if ontology_classes_dict(ontology):
            ontology.destroy()
            ontology = world.get_ontology(
                os.path.join(settings.MEDIA_ROOT, str(ontology_file))
            ).load()
    else:
        ontology = default_world.get_ontology(
            os.path.join(settings.MEDIA_ROOT, str(ontology_file))
        ).load()
        if ontology_classes_dict(ontology):
            try:
                ontology.destroy()
            except Exception as e:
                print(f"Ontology classes: {(ontology, e)}")
            ontology = default_world.get_ontology(
                os.path.join(settings.MEDIA_ROOT, str(ontology_file))
            ).load()
    return ontology


class MakeTree:
    def __init__(self, data):
        self.data = data
        self.children = []

    def add_child(self, child_node):
        self.children.append(child_node)


def tree_to_dict(node):
    result = {"node_name": node.data}
    if node.children:
        result["children"] = [tree_to_dict(child) for child in node.children]
    return result


def ontology_data_to_dict_tree(
    ontology,
    root,
    class_first_name=None,
    class_second_name=None,
):
    """Converts the daa classes of an ontology to a dict tree
    :param ontology: Ontology in owl/rdf format
    :type ontology: owlready2.Ontology
    :return: tree of purposes
    :rtype: dict
    """
    class_a = []
    class_b = []

    if root is None:
        return {"error": "Root class is not defined"}

    if class_first_name is not None:
        class_a = list(ontology_classes_dict(ontology)[class_first_name].subclasses())
    if class_second_name is not None:
        class_b = list(ontology_classes_dict(ontology)[class_second_name].subclasses())

    combined_data = class_a + class_b

    if not combined_data:
        return {}

    root = MakeTree(prettyfy(str(ontology_classes_dict(ontology)[root]), False))
    for cls in combined_data:
        root_child = MakeTree(prettyfy(str(cls), False))
        root.children.append(root_child)
        root_child_has_subclasses = list(cls.subclasses())
        if root_child_has_subclasses:
            for childcls in root_child_has_subclasses:
                root_child.children.append(MakeTree(prettyfy(str(childcls), False)))
    dict_tree = tree_to_dict(root)
    return dict_tree


def get_leaf_node_names(node):
    """Returns the list of leaf node names from the ontology
    Input is the tree data constructed based on data_context ontology.
    Example:
      'node_name': 'DataSource',
    'children': [
        {'node_name': 'Humidity'},
        {'node_name': 'Magnetometer'},
        {
            'node_name': 'PersonalData',
            'children': [
                {'node_name': 'Email'},
                {'node_name': 'Name'},
                {'node_name': 'SocialSecurityNumber'}
            ]
        },
        {'node_name': 'IPAddress'}
    ]

    Output:
     ['Humidity', 'Magnetometer', 'Email', 'Name', 'SocialSecurityNumber', 'IPAddress']

    :param node: Tree format
    :type node: MakeTree
    :return:  leaf node names
    :rtype: list
    """
    if "children" not in node:
        return [node["node_name"]]
    else:
        # Recursive case: node has children
        leaf_node_names = []
        for child in node["children"]:
            leaf_node_names.extend(get_leaf_node_names(child))
        return leaf_node_names

def get_fields_from_datasets(dataset,ttl_file_path):
    # Parse TTL content
    g = Graph()
    g.parse(ttl_file_path, format="ttl")


    # Define namespaces
    # odrl = Namespace("http://www.w3.org/ns/odrl/2/#")

    # Query actions
    actions_query = f"""
        PREFIX ex: <http://example.org/datasets/>
        PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT ?columnName ?columnType ?columnDescription ?columnExample
        WHERE {{
            <{dataset}> rdf:type ex:Dataset ;
                ex:hasColumn [ rdf:type ex:Column ;
                               ex:columnName ?columnName ;
                               ex:columnDataType ?columnType ;
                               ex:columnDescription ?columnDescription ;
                               ex:columnExample ?columnExample ] .
        }}
    """
#     actions_query = """
#     SELECT *
#     WHERE {
# ?s ?p ?o
#     }
#         """

    fields = [
        {"columnName": row.columnName.value,"columnType": row.columnType.value,"columnDescription": row.columnDescription.value,"columnExample": row.columnExample.value}
        for row in g.query(actions_query)
    ]

    return fields

def get_actions_from_ttl(ttl_file_path):
    # Load the TTL file into an RDF graph
    g = Graph()
    g.parse(ttl_file_path, format="turtle")

    # Define the relevant namespaces
    # odrl = Namespace("http://www.w3.org/ns/odrl/2/#")
    skos = Namespace("http://www.w3.org/2004/02/skos/core#")

    # Query for actions in the skos:Collection
    actions_query = """
    SELECT ?action
    WHERE {
      ?collection a skos:Collection ;
                  skos:member ?action .
    }
    """

    # Execute the query
    actions_result = g.query(actions_query, initNs={"skos": skos})

    # Extract and return the list of actions
    actions_list = [str(action) for action, in actions_result]
    return actions_list


def get_subclasses_of_rule2(ttl_file_path):
    # Load the TTL file into an RDF graph
    g = Graph()
    g.parse(ttl_file_path, format="turtle")

    # Define the relevant namespaces
    odrl = Namespace("http://www.w3.org/ns/odrl/2/#")
    rdfs = Namespace("http://www.w3.org/2000/01/rdf-schema#")

    # Query for subclasses of :Rule
    subclasses_query = """
    SELECT ?subclass
    WHERE {
      ?subclass a rdfs:Class ;
                rdfs:subClassOf odrl:Rule .
    }
    """

    # Execute the query
    subclasses_result = g.query(subclasses_query, initNs={"odrl": odrl, "rdfs": rdfs})

    # Extract and return the list of subclasses of :Rule
    subclasses_list = [str(subclass) for subclass, in subclasses_result]
    return subclasses_list


def get_rules_from_odrl(ttl_file_path):
    # Parse TTL data
    g = Graph()
    g.parse(ttl_file_path, format="xml")

    # Define namespace
    # odrl = Namespace(
    #     "http://www.w3.org/ns/odrl/2/#"
    # )  # Replace with the actual namespace
    # rdfs = Namespace("http://www.w3.org/2000/01/rdf-schema#")

    # Query for subclasses of :Rule
    subclasses_query = """
        SELECT ?subClass ?label
        WHERE {
          ?subClass rdfs:subClassOf odrl:Rule ;
                    rdfs:label ?label .
        }
    """

    # Execute the query
    subclasses_result = g.query(subclasses_query)

    # Convert results to a list of dictionaries
    result_list = [
        {"uri": str(row.subClass), "label": str(row.label)} for row in subclasses_result
    ]

    return result_list


def get_actors_from_dpv(ttl_file_path):
    g = Graph()
    g.parse(ttl_file_path, format="xml")

    # dpv = Namespace("https://w3id.org/dpv#")
    # skos = Namespace("http://www.w3.org/2004/02/skos/core#")

    # Query for subclasses of :Rule
    subclasses_query = """
        SELECT ?subClass ?label
        WHERE {
          ?subClass rdfs:subClassOf+ <https://w3id.org/dpv/owl#LegalEntity> .
          ?subClass rdfs:label ?label .
        }
    """

    # Execute the query
    subclasses_result = g.query(subclasses_query)

    # Convert results to a list of dictionaries
    result_list = [
        {"uri": str(row.subClass), "label": str(row.label)} for row in subclasses_result
    ]

    return result_list


def get_purposes_from_dpv(ttl_file_path):
    # Parse TTL data
    g = Graph()
    g.parse(ttl_file_path, format="xml")

    # Define namespace
    # dpv = Namespace("https://w3id.org/dpv#")  # Replace with the actual namespace
    # skos = Namespace("http://www.w3.org/2004/02/skos/core#")

    # Query for subclasses of :Rule
    subclasses_query = """
        SELECT ?subClass ?label
        WHERE {
          ?subClass rdfs:subClassOf <https://w3id.org/dpv/owl#Purpose> .
          ?subClass rdfs:label ?label .
        }
    """

    # Execute the query
    subclasses_result = g.query(subclasses_query)

    # Convert results to a list of dictionaries
    result_list = [
        {"uri": str(row.subClass), "label": str(row.label)} for row in subclasses_result
    ]

    return result_list


def get_constraints_types_from_odrl(ttl_file_path):
    # Parse TTL data
    g = Graph()
    g.parse(ttl_file_path, format="xml")

    # Query for subclasses of :Rule
    query = """
        SELECT ?leftoperand ?label
        WHERE {
          ?leftoperand a odrl:LeftOperand, owl:NamedIndividual ;
                    rdfs:label ?label .
        }
    """

    # Execute the query
    result = g.query(query)

    # Convert results to a list of dictionaries
    result_list = [
        {"uri": str(row.leftoperand), "label": str(row.label)} for row in result
    ]

    return result_list


def get_dataset_titles_and_uris(ttl_file_path):
    # Load the TTL file into an RDF graph
    g = Graph()
    g.parse(ttl_file_path, format="turtle")

    # Define the relevant namespaces
    ex = Namespace("http://example.org/datasets/")
    dct = Namespace("http://purl.org/dc/terms/")

    # Query for dataset titles and URIs
    query = """
    SELECT ?dataset ?title
    WHERE {
      ?dataset rdf:type ex:Dataset ;
               dct:title ?title .
    }
    """

    # Execute the query
    result = g.query(query, initNs={"ex": ex, "dct": dct})

    # Extract and return the list of dataset titles and URIs
    dataset_info_list = [
        {"uri": str(dataset), "label": str(title)} for dataset, title in result
    ]
    return dataset_info_list


def get_actions_from_odrl(ttl_file_path):
    # Parse TTL content
    g = Graph()
    g.parse(ttl_file_path, format="xml")

    # Define namespaces
    # odrl = Namespace("http://www.w3.org/ns/odrl/2/#")

    # Query actions
    actions_query = """
    SELECT ?action ?label
    WHERE {
        ?action a odrl:Action.
        ?action rdfs:label ?label.
    }
    """

    actions = [
        {"uri": str(row.action), "label": str(row.label)}
        for row in g.query(actions_query)
    ]

    return actions


def get_operators_from_odrl(ttl_file_path):
    # Parse TTL content
    g = Graph()
    g.parse(ttl_file_path, format="xml")

    # Define namespaces
    # odrl = Namespace("http://www.w3.org/ns/odrl/2/#")

    # Query actions
    actions_query = """
    SELECT ?action ?label
    WHERE {
        ?action a odrl:Operator.
        ?action rdfs:label ?label.
    }
    """

    actions = [
        {"uri": str(row.action), "label": str(row.label)}
        for row in g.query(actions_query)
    ]

    return actions

def get_properties_of_a_class(class_uri, ttl_file_path):
    # Parse TTL content
    g = Graph()
    g.parse(str(ttl_file_path), format="ttl")
    if "/" in class_uri:
        class_uri = "<" + class_uri + ">"
    properties_query = f"""
        PREFIX dpv: <https://w3id.org/dpv/owl##>
        PREFIX cc: <http://creativecommons.org/ns#>
        PREFIX odrl: <http://www.w3.org/ns/odrl/2/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
        PREFIX owl: <http://www.w3.org/2002/07/owl#>

        SELECT ?property ?label
        WHERE {{
          ?property rdf:type owl:DatatypeProperty ;
                    rdfs:domain {class_uri} ;
                    rdfs:label ?label .
        }}
    """
    properties2 = list(g.query("select * where {?s ?p ?o}"))
    properties = [
        {"uri": str(row.property), "label": str(row.label)}
        for row in g.query(properties_query)
    ]
    return properties



def convert_list_to_odrl_jsonld(data_list):
    odrl_rules = []
    policy = {
        "rule": odrl_rules,
    }
    for data in data_list:
        ruleType = "rule"
        odrl_jsonld = {
            "action": data["action"].split("/")[-1],  # Extract the action type
            "assignee": data["actor"].split("#")[-1],
            "constraint": [],
        }
        for constraint in data["constraints"]:
            odrl_jsonld["constraint"].append(
                {
                    "leftOperand": constraint["type"].split("/")[
                        -1
                    ],  # Extract the constraint type
                    "operator": constraint["operator"].split("/")[-1],
                    "rightOperand": constraint["value"],
                }
            )
        policy[ruleType].append(odrl_jsonld)
    if len(policy["rule"]) == 0:
        del policy["rule"]
    return policy



def convert_list_to_odrl_jsonld_depr(data_list):
    odrl_rules = []
    policy = {
        "rule": odrl_rules,
    }
    for data in data_list:
        if data["action"] is not None and data["actor"] is not None and data["target"] is not None:
            ruleType = "rule"
            targetrefinement = []
            target = ""
            if data["targetrefinements"] is not None:
                target = {"source" : data["target"].split("/")[-1],"refinement": targetrefinement}
            else:
                target = data["target"].split("/")[-1]

            odrl_jsonld = {
                "action": data["action"].split("/")[-1],  # Extract the action type
                "assignee": data["actor"].split("/")[-1],
                "target": target,
                "constraint": [],
            }

            for constraint in data["targetrefinements"]:
                if constraint["operator"] is not None:
                    odrl_jsonld["target"]["refinement"].append(
                        {
                            "leftOperand": constraint["type"].split("/")[
                                -1
                            ],  # Extract the constraint type
                            "operator": constraint["operator"].split("/")[-1],
                            "rightOperand": constraint["value"],
                        }
                    )
            for constraint in data["constraints"]:
                if constraint["operator"] is not None:
                    odrl_jsonld["constraint"].append(
                        {
                            "leftOperand": constraint["type"].split("/")[
                                -1
                            ],  # Extract the constraint type
                            "operator": constraint["operator"].split("/")[-1],
                            "rightOperand": constraint["value"],
                        }
                    )
            policy[ruleType].append(odrl_jsonld)
    if len(policy["rule"]) == 0:
        del policy["rule"]
    return policy

def convert_list_to_odrl_jsonld_no_user(data_list):
    odrl_permissions = []
    odrl_prohibitions = []
    odrl_obligations = []
    odrl_duties = []
    odrl_rules = []

    policy = {
        "permission": odrl_permissions,
        "prohibition": odrl_prohibitions,
        "obligation": odrl_obligations,
        "duty": odrl_duties,
        "rule": odrl_rules,
        "uid": "http://example.org/policy-" + str(uuid.uuid4()),
        "@context": "http://www.w3.org/ns/odrl.jsonld",
        "@type": "http://www.w3.org/ns/odrl/2/Policy",
    }
    for data in data_list:
        if data["action"] is not None and data["actor"] is not None and data["target"] is not None:
            if "rule" in data:
                ruleType = str(data["rule"].split("/")[-1]).lower()

                if len(data["actorrefinements"])>0:
                    actor = {"source": data["actor"], "refinement": []}
                else:
                    actor = data["actor"]
                if len(data["actionrefinements"])>0:
                    action = {"source": data["action"], "refinement": []}
                else:
                    action = data["action"]


                if len(data["targetrefinements"])>0:
                    target = {"source": data["target"], "refinement": []}
                else:
                    target = data["target"]

                odrl_jsonld = {
                    "action": action,  # Extract the action type
                    "assignee": actor,
                    "target": target,
                    "constraint": [],
                }

                if len(data["purposerefinements"])>0:

                    purpose = data["purpose"]
                    purposerefinements = {"and":[]}
                    purposerefinements["and"].append({
                        "leftOperand": "purpose",
                        "operator": "http://www.w3.org/ns/odrl/2/eq",
                        "rightOperand": purpose,
                    })

                    for constraint in data["purposerefinements"]:

                        if constraint["operator"] is not None:
                            purposerefinements["and"].append(
                                {
                                    "leftOperand": constraint["type"].split("#")[
                                        -1
                                    ],  # Extract the constraint type
                                    "operator": constraint["operator"],
                                    "rightOperand": constraint["value"],
                                }
                            )

                    odrl_jsonld["constraint"].append(purposerefinements)
                else:
                    purpose = data["purpose"]
                    odrl_jsonld["constraint"].append(
                        {
                            "leftOperand": "purpose",
                            "operator": "http://www.w3.org/ns/odrl/2/eq",
                            "rightOperand": purpose,
                        }
                    )
            else:
                ruleType = "rule"
                odrl_jsonld = {
                    "action": data["action"],  # Extract the action type
                    "assignee": data["actor"],
                    "constraint": [],
                }
            if "query" in data:
                if data["query"] != '':
                    odrl_jsonld["constraint"].append(
                        {
                            "leftOperand": "ex:query",
                            "operator": "eq",
                            "rightOperand": data["query"],
                        }
                    )
            for constraint in data["constraints"]:
                if constraint["operator"] is not None:
                    odrl_jsonld["constraint"].append(
                        {
                            "leftOperand": constraint["type"].split("#")[
                                -1
                            ],  # Extract the constraint type
                            "operator": constraint["operator"],
                            "rightOperand": constraint["value"],
                        }
                    )
            for constraint in data["actorrefinements"]:
                if constraint["operator"] is not None:
                    print(constraint)
                    print(odrl_jsonld)
                    print(odrl_jsonld["assignee"]["refinement"])
                    print(constraint["type"])
                    print(constraint["operator"])
                    print(constraint["value"])
                    odrl_jsonld["assignee"]["refinement"].append(
                        {
                            "leftOperand": constraint["type"].split("#")[
                                -1
                            ],  # Extract the constraint type
                            "operator": constraint["operator"],
                            "rightOperand": constraint["value"],
                        }
                    )
            for constraint in data["actionrefinements"]:
                if constraint["operator"] is not None:
                    odrl_jsonld["action"]["refinement"].append(
                        {
                            "leftOperand": constraint["type"].split("#")[
                                -1
                            ],  # Extract the constraint type
                            "operator": constraint["operator"],
                            "rightOperand": constraint["value"],
                        }
                    )
            for constraint in data["targetrefinements"]:
                if constraint["operator"] is not None:
                    odrl_jsonld["target"]["refinement"].append(
                        {
                            "leftOperand": constraint["type"].split("#")[
                                -1
                            ],  # Extract the constraint type
                            "operator": constraint["operator"],
                            "rightOperand": constraint["value"],
                        }
                    )
            policy[ruleType].append(odrl_jsonld)
    if len(policy["permission"]) == 0:
        del policy["permission"]
    if len(policy["prohibition"]) == 0:
        del policy["prohibition"]
    if len(policy["obligation"]) == 0:
        del policy["obligation"]
    if len(policy["duty"]) == 0:
        del policy["duty"]
    if len(policy["rule"]) == 0:
        del policy["rule"]
    return policy

def _fetch_valid_status(odrl_policy):
    edge_options = webdriver.EdgeOptions()
    edge_options.add_argument("--headless")

    driver = webdriver.Edge(options=edge_options)
    driver.get("https://odrlapi.appspot.com/")

    WebDriverWait(driver, 50).until(EC.presence_of_element_located((By.ID, "pgn")))
    print(odrl_policy)

    text_area = driver.find_element(By.ID, "pgn")
    text_area.send_keys(odrl_policy)

    time.sleep(3)

    validate_button = driver.find_element(By.XPATH, '//a[@id="boton2"]')
    validate_button.click()

    time.sleep(25)

    WebDriverWait(driver, 100).until(
        EC.invisibility_of_element_located(
            (By.XPATH, '//div[@id="salida"]/pre[text()="No output"]')
        )
    )

    result_element = driver.find_element(By.ID, "salida")
    result = result_element.text

    driver.implicitly_wait(0)
    driver.quit()

    return result
