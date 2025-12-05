import rdflib
from rdflib import Graph, Namespace, RDF, RDFS, URIRef, BNode, Literal
from rdflib.namespace import XSD, OWL, SKOS
import os
from datetime import datetime


class ODRLPolicyChecker:
    """
    A class to check compatibility between ODRL policies.
    """

    def __init__(self, ontology_file=None):
        """
        Initialize the ODRL policy checker.

        Args:
            ontology_file: Path to the ontology file (string)
        """
        # Define ODRL namespace
        self.ODRL = Namespace("http://www.w3.org/ns/odrl/2/")
        self.ontology_file = ontology_file
        self.combined_graph = None

    def check_policy_compatibility(self, policy1_turtle, policy2_turtle):
        """
        Check compatibility between two ODRL policies in Turtle format.

        Args:
            policy1_turtle: First ODRL policy in Turtle format (string)
            policy2_turtle: Second ODRL policy in Turtle format (string)

        Returns:
            bool: True if policies are compatible, False otherwise
            str: Reason for incompatibility if policies are not compatible
        """
        # # Parse policies
        # g1 = Graph()
        # g1.parse(data=policy1_turtle, format="turtle")
        #
        # g2 = Graph()
        # g2.parse(data=policy2_turtle, format="turtle")

        g1 = policy1_turtle
        g2 = policy2_turtle
        # Create a combined graph with ontology if provided
        self.combined_graph = Graph()
        self.combined_graph += g1
        self.combined_graph += g2

        if self.ontology_file and os.path.exists(self.ontology_file):
            self._load_ontology()

        # Extract policy URIs
        policy1_uri = None
        policy2_uri = None

        for s, p, o in g1.triples((None, RDF.type, self.ODRL.Policy)):
            policy1_uri = s
            break

        for s, p, o in g2.triples((None, RDF.type, self.ODRL.Policy)):
            policy2_uri = s
            break

        if not policy1_uri or not policy2_uri:
            return False, "Could not find policy URIs in the provided Turtle data"

        per_res = False
        return_obj = None
        # Rule 1: For all permissions x in POLICY1, If exists_larger(x,'permission', POLICY2) == False, return False
        p_list = self._get_rules_by_type(g2, policy2_uri, self.ODRL.permission)
        for permission in p_list:
            if self._exists_larger(permission, g2, 'permission', g1, policy1_uri):
                per_res = per_res or True
        if len(p_list) == 0:
            per_res = True

        if not per_res:
            return per_res, "Rule 1: Consumer asks for permission, but there’s no permission from the provider that covers everything the consumer asks for."

        # Rule 2: For all permissions x in POLICY2, If exists_intersect(x,'prohibition', POLICY1) = True return False
        for permission in self._get_rules_by_type(g2, policy2_uri, self.ODRL.permission):
            if self._exists_intersect(permission, g2, 'prohibition', g1, policy1_uri):
                return False, "Rule 2: Consumer asks for permission for something that is entirely or in part forbidden by the provider."

        # Rule 3: For all obligations x in POLICY2, If exists_intersect(x,'prohibition', POLICY1) = True return False
        for obligation in self._get_rules_by_type(g2, policy2_uri, self.ODRL.obligation):
            if self._exists_intersect(obligation, g2, 'prohibition', g1, policy1_uri):
                return False, "Rule 3: Consumer is committing to doing something that is forbidden, entirely or in part, by the provider."

        ob_res = True
        # Rule 4: For all obligations x in POLICY2, If exists_larger(x,'permission', POLICY1) == False, return False
        for obligation in self._get_rules_by_type(g2, policy2_uri, self.ODRL.obligation):
            ob_res = False
            if not self._exists_larger(obligation, g2, 'permission', g1, policy1_uri):
                ob_res = ob_res or False
            else:
                ob_res = ob_res or True
        if not ob_res:
            return False, "Rule 4: The consumer is committing to doing something that is not explicitly permitted by the provider."

        # # Rule 4: For all obligations x in POLICY1, If exists_larger(x,'permission', POLICY2) == False, return False
        # for obligation in self._get_rules_by_type(g1, policy1_uri, self.ODRL.obligation):
        #     if not self._exists_larger(obligation, g1, 'permission', g2, policy2_uri):
        #         return False, "Obligation in policy1 doesn't have a larger permission in policy2"

        # Rule 5: For all prohibitions x in POLICY1, If exists_larger(x,'prohibition', POLICY2) == False, return False
        for prohibition in self._get_rules_by_type(g1, policy1_uri, self.ODRL.prohibition):
            if not self._exists_larger(prohibition, g2, 'prohibition', g1, policy1_uri):
                return False, "Rule 5: The consumer is not explicitly agreeing to a complete prohibition set by the provider."

        # Rule 6: For all obligations x in POLICY1, If exists_smaller(x,'obligation', POLICY1) == False, return False
        for obligation in self._get_rules_by_type(g1, policy1_uri, self.ODRL.obligation):
            if not self._exists_smaller(obligation, g2, 'obligation', g1, policy1_uri):
                return False, "Rule 6: The consumer is not explicitly agreeing to a complete obligation set by the provider."

        # If all rules pass, policies are compatible
        return True, "Policies are compatible"

    def _load_ontology(self):
        """
        Load ontology from file into the combined graph.
        """
        format_map = {
            '.rdf': 'xml',
            '.owl': 'xml',
            '.ttl': 'turtle',
            '.n3': 'n3',
            '.nt': 'nt',
            '.jsonld': 'json-ld'
        }
        file_ext = os.path.splitext(self.ontology_file)[1].lower()
        file_format = format_map.get(file_ext, 'xml')  # Default to XML/RDF format

        try:
            self.combined_graph.parse(self.ontology_file, format=file_format)
            print(f"Successfully loaded ontology from {self.ontology_file}")

            # Print some stats about the ontology
            num_triples = len(self.combined_graph)
            print(f"Total triples in combined graph: {num_triples}")

            # Check for ODRL actions and includedIn relationships
            actions = list(self.combined_graph.subjects(RDF.type, self.ODRL.Action))
            included_relations = list(self.combined_graph.subject_objects(self.ODRL.includedIn))

            print(f"Found {len(actions)} ODRL Actions in ontology")
            print(f"Found {len(included_relations)} includedIn relationships in ontology")

        except Exception as e:
            print(f"Error loading ontology: {str(e)}")

    def _get_rules_by_type(self, graph, policy_uri, rule_type):
        """
        Extract rules of a specific type from an ODRL policy.

        Args:
            graph: RDF graph containing the policy
            policy_uri: URI of the policy
            rule_type: Type of rules to extract (ODRL.permission, ODRL.prohibition, or ODRL.obligation)

        Returns:
            list: List of BNodes representing rules of the specified type
        """
        rules = []

        for _, _, rule_node in graph.triples((policy_uri, rule_type, None)):
            rules.append(rule_node)

        return rules

    def _extract_rule_components(self, graph, rule_node):
        """
        Extract components (target, action, constraints) of a rule.

        Args:
            graph: RDF graph containing the rule
            rule_node: BNode representing the rule

        Returns:
            dict: Components of the rule
        """
        # Extract target
        target = None
        for _, _, target_node in graph.triples((rule_node, self.ODRL.target, None)):
            target = self._extract_target(graph, target_node)

        # Extract action
        action = None
        for _, _, action_node in graph.triples((rule_node, self.ODRL.action, None)):
            action = self._extract_action(graph, action_node)

        # Extract constraints
        constraints = []
        for _, _, constraint_node in graph.triples((rule_node, self.ODRL.constraint, None)):
            constraint = self._extract_constraint(graph, constraint_node)
            if constraint:
                constraints.append(constraint)

        # Extract assignee if present
        assignee = None
        for _, _, assignee_node in graph.triples((rule_node, self.ODRL.assignee, None)):
            assignee = self._extract_assignee(graph, assignee_node)

        # Extract refinements if any
        refinements = []
        if action and isinstance(action, dict) and 'refinement' in action:
            refinements = action['refinement']

        # Additional refinements directly on the rule
        for _, _, refinement_node in graph.triples((rule_node, self.ODRL.refinement, None)):
            refinement = self._extract_constraint(graph, refinement_node)
            if refinement:
                refinements.append(refinement)

        return {
            'target': target,
            'action': action,
            'constraint': constraints,
            'assignee': assignee,
            'refinement': refinements
        }

    def _extract_target(self, graph, target_node):
        """
        Extract target information from a target node.

        Args:
            graph: RDF graph containing the target
            target_node: BNode representing the target

        Returns:
            dict: Target information
        """
        target_info = {'type': None, 'value': None}

        # Check if target has a type
        for _, _, target_type in graph.triples((target_node, RDF.type, None)):
            target_info['type'] = str(target_type)

        # Get the value of the target
        for _, _, target_value in graph.triples((target_node, RDF.value, None)):
            target_info['value'] = str(target_value)

        return target_info

    def _extract_action(self, graph, action_node):
        """
        Extract action information from an action node.

        Args:
            graph: RDF graph containing the action
            action_node: BNode representing the action

        Returns:
            dict or str: Action information
        """
        action_info = {'value': None, 'refinement': []}

        # Get the primary action
        for _, _, action_value in graph.triples((action_node, RDF.value, None)):
            action_info['value'] = str(action_value)

        # Get any refinements
        for _, _, refinement_node in graph.triples((action_node, self.ODRL.refinement, None)):
            refinement = self._extract_constraint(graph, refinement_node)
            if refinement:
                action_info['refinement'].append(refinement)

        # If there are no refinements, return just the action value for simplicity
        if not action_info['refinement']:
            return action_info['value']

        return action_info

    def _extract_constraint(self, graph, constraint_node):
        """
        Extract constraint information from a constraint node.

        Args:
            graph: RDF graph containing the constraint
            constraint_node: BNode representing the constraint

        Returns:
            dict: Constraint information
        """
        constraint_info = {}

        # Extract left operand
        for _, _, left_operand in graph.triples((constraint_node, self.ODRL.leftOperand, None)):
            constraint_info['leftOperand'] = str(left_operand)

        # Extract operator
        for _, _, operator in graph.triples((constraint_node, self.ODRL.operator, None)):
            constraint_info['operator'] = str(operator)

        # Extract right operand
        for _, _, right_operand in graph.triples((constraint_node, self.ODRL.rightOperand, None)):
            if isinstance(right_operand, Literal):
                constraint_info['rightOperand'] = right_operand.value
                constraint_info['datatype'] = str(right_operand.datatype) if right_operand.datatype else None
            else:
                constraint_info['rightOperand'] = str(right_operand)

        return constraint_info

    def _extract_assignee(self, graph, assignee_node):
        """
        Extract assignee information from an assignee node.

        Args:
            graph: RDF graph containing the assignee
            assignee_node: BNode representing the assignee

        Returns:
            dict: Assignee information
        """
        assignee_info = {'type': None, 'value': None}

        # Check if assignee has a type
        for _, _, assignee_type in graph.triples((assignee_node, RDF.type, None)):
            assignee_info['type'] = str(assignee_type)

        # Get the value of the assignee
        for _, _, assignee_value in graph.triples((assignee_node, RDF.value, None)):
            assignee_info['value'] = str(assignee_value)

        return assignee_info

    def _exists_larger(self, rule_node, rule_graph, rule_type_str, target_graph, target_policy_uri):
        """
        Check if there exists a rule in target_policy of type rule_type that is larger than or equal to rule.

        Args:
            rule_node: BNode representing the rule
            rule_graph: RDF graph containing the rule
            rule_type_str: Type of rules to check in target_policy ('permission', 'prohibition', or 'obligation')
            target_graph: RDF graph containing the target policy
            target_policy_uri: URI of the target policy

        Returns:
            bool: True if a larger rule exists, False otherwise
        """
        rule_type_map = {
            'permission': self.ODRL.permission,
            'prohibition': self.ODRL.prohibition,
            'obligation': self.ODRL.obligation
        }

        rule_type = rule_type_map[rule_type_str]
        rule_info = self._extract_rule_components(rule_graph, rule_node)

        target_rules = self._get_rules_by_type(target_graph, target_policy_uri, rule_type)

        for target_rule in target_rules:
            target_rule_info = self._extract_rule_components(target_graph, target_rule)
            if self._is_rule_larger_or_equal(target_rule_info, rule_info):
                return True
        return False

    def _exists_smaller(self, rule_node, rule_graph, rule_type_str, target_graph, target_policy_uri):
        """
        Check if there exists a rule in target_policy of type rule_type that is smaller than or equal to rule.

        Args:
            rule_node: BNode representing the rule
            rule_graph: RDF graph containing the rule
            rule_type_str: Type of rules to check in target_policy ('permission', 'prohibition', or 'obligation')
            target_graph: RDF graph containing the target policy
            target_policy_uri: URI of the target policy

        Returns:
            bool: True if a smaller rule exists, False otherwise
        """
        rule_type_map = {
            'permission': self.ODRL.permission,
            'prohibition': self.ODRL.prohibition,
            'obligation': self.ODRL.obligation
        }

        rule_type = rule_type_map[rule_type_str]
        rule_info = self._extract_rule_components(rule_graph, rule_node)

        target_rules = self._get_rules_by_type(target_graph, target_policy_uri, rule_type)

        for target_rule in target_rules:
            target_rule_info = self._extract_rule_components(target_graph, target_rule)
            if self._is_rule_larger_or_equal(rule_info, target_rule_info):
                return True
        return False

    def _exists_intersect(self, rule_node, rule_graph, rule_type_str, target_graph, target_policy_uri):
        """
        Check if there exists a rule in target_policy of type rule_type that intersects with rule.

        Args:
            rule_node: BNode representing the rule
            rule_graph: RDF graph containing the rule
            rule_type_str: Type of rules to check in target_policy ('permission', 'prohibition', or 'obligation')
            target_graph: RDF graph containing the target policy
            target_policy_uri: URI of the target policy

        Returns:
            bool: True if an intersecting rule exists, False otherwise
        """
        rule_type_map = {
            'permission': self.ODRL.permission,
            'prohibition': self.ODRL.prohibition,
            'obligation': self.ODRL.obligation
        }

        rule_type = rule_type_map[rule_type_str]
        rule_info = self._extract_rule_components(rule_graph, rule_node)

        target_rules = self._get_rules_by_type(target_graph, target_policy_uri, rule_type)

        for target_rule in target_rules:
            target_rule_info = self._extract_rule_components(target_graph, target_rule)
            if self._rules_intersect(rule_info, target_rule_info):
                return True

        return False

    def _is_rule_larger_or_equal(self, rule1, rule2):
        """
        Check if rule1 is larger than or equal to rule2.
        A rule is larger if it permits at least the same actions on the same targets
        with the same or broader constraints.

        Args:
            rule1: First ODRL rule (dictionary)
            rule2: Second ODRL rule (dictionary)

        Returns:
            bool: True if rule1 is larger than or equal to rule2, False otherwise
        """
        # Check if the actions are compatible
        if not self._actions_compatible(rule1['action'], rule2['action']):
            return False

        # Check if the targets are compatible
        if not self._is_target_larger_or_equal(rule1['target'], rule2['target']):
            return False

        # Check if the assignees are compatible
        if rule1['assignee'] and rule2['assignee'] and not self._are_assignees_compatible(rule1['assignee'],
                                                                                          rule2['assignee']):
            return False

        # Check if the constraints in rule1 are subset of constraints in rule2
        if not self._are_constraints_larger_or_equal(rule1['constraint'], rule2['constraint']):
            return False

        # Check if the refinements in rule1 are subset of refinements in rule2
        if not self._are_constraints_larger_or_equal(rule1['refinement'], rule2['refinement']):
            return False

        return True

    def _actions_compatible(self, action1, action2):
        """
        Check if two actions are compatible, considering subclass/superclass/includedIn relationships.

        Args:
            action1: First action (string or dict)
            action2: Second action (string or dict)

        Returns:
            bool: True if actions are compatible, False otherwise
        """
        # If either is None, we can't compare
        if action1 is None or action2 is None:
            return False

        # Extract action values
        action1_value = action1['value'] if isinstance(action1, dict) else action1
        action2_value = action2['value'] if isinstance(action2, dict) else action2

        # Check direct equality
        if action1_value == action2_value:
            return True

        # Check for superclass/subclass relationship
        if self._is_included_in(action1_value, action2_value) or self._is_included_in(action2_value, action1_value):
            return True

        # If both are dictionaries with refinements, check them too
        if isinstance(action1, dict) and isinstance(action2, dict):
            refinements1 = action1.get('refinement', [])
            refinements2 = action2.get('refinement', [])

            # Check if refinements are compatible
            if not self._are_constraints_larger_or_equal(refinements1, refinements2):
                return False

        return False

    def _is_included_in(self, class1, class2):
        """
        Check if class1 is included in class2 through ODRL includedIn, subClassOf, or equivalentClass relationships.

        Args:
            class1: URI of the first class/action
            class2: URI of the second class/action

        Returns:
            bool: True if class1 is included in class2, False otherwise
        """
        if class1 == class2:
            return True

        if not self.combined_graph:
            return False

        try:
            # Check direct includedIn relationship
            if (URIRef(class1), self.ODRL.includedIn, URIRef(class2)) in self.combined_graph:
                return True

            # Check direct subclass relationship
            if (URIRef(class1), RDFS.subClassOf, URIRef(class2)) in self.combined_graph:
                return True

            # Check equivalence
            if (URIRef(class1), OWL.equivalentClass, URIRef(class2)) in self.combined_graph:
                return True

            # Check transitive includedIn relationships
            for _, _, included_in in self.combined_graph.triples((URIRef(class1), self.ODRL.includedIn, None)):
                if self._is_included_in(str(included_in), class2):
                    return True

            # Check transitive subclass relationships
            for _, _, superclass in self.combined_graph.triples((URIRef(class1), RDFS.subClassOf, None)):
                if self._is_included_in(str(superclass), class2):
                    return True
        except Exception as e:
            print(f"Error in is_included_in: {str(e)}")

        return False

    def _is_target_larger_or_equal(self, target1, target2):
        """
        Check if target1 is larger than or equal to target2.

        Args:
            target1: First ODRL target (dictionary)
            target2: Second ODRL target (dictionary)

        Returns:
            bool: True if target1 is larger than or equal to target2, False otherwise
        """
        # If either is None, we can't compare
        if target1 is None or target2 is None:
            return False

        # Check if they have the same type or compatible types
        if target1['type'] != target2['type'] and not self._is_included_in(target1['type'], target2['type']):
            return False

        # Check if they have the same value or if the value is included in the other
        if target1['value'] != target2['value'] and not self._is_included_in(target1['value'], target2['value']):
            return False

        return True

    def _are_assignees_compatible(self, assignee1, assignee2):
        """
        Check if two assignees are compatible.

        Args:
            assignee1: First assignee (dictionary)
            assignee2: Second assignee (dictionary)

        Returns:
            bool: True if assignees are compatible, False otherwise
        """
        # If either is None, we consider them compatible
        if assignee1 is None or assignee2 is None:
            return True

        # Check if they have the same type or compatible types
        if assignee1['type'] != assignee2['type'] and not self._is_included_in(assignee1['type'], assignee2['type']):
            return False

        # Check if they have the same value or compatible values
        if assignee1['value'] != assignee2['value'] and not self._is_included_in(assignee1['value'],
                                                                                 assignee2['value']):
            return False

        return True

    def _are_constraints_larger_or_equal(self, constraints1, constraints2):
        """
        Check if constraints1 are larger than or equal to constraints2.
        Constraints are larger if they are less restrictive or equal.

        Args:
            constraints1: List of constraints from first rule
            constraints2: List of constraints from second rule

        Returns:
            bool: True if constraints1 are larger than or equal to constraints2, False otherwise
        """
        # If there are no constraints in rule2, rule1 is larger or equal
        if not constraints2:
            return True

        # If there are constraints in rule2 but none in rule1, rule1 is larger (less restrictive)
        if not constraints1 and constraints2:
            return True

        # For each constraint in rule2, there must be a compatible constraint in rule1
        for constraint2 in constraints2:
            found_compatible = False

            for constraint1 in constraints1:
                if self._is_constraint_compatible(constraint1, constraint2):
                    found_compatible = True
                    break

            if not found_compatible:
                return False

        return True

    def _is_constraint_compatible(self, constraint1, constraint2):
        """
        Check if constraint1 is compatible with constraint2.

        Args:
            constraint1: First ODRL constraint (dictionary)
            constraint2: Second ODRL constraint (dictionary)

        Returns:
            bool: True if constraints are compatible, False otherwise
        """
        # Check if they refer to the same property or to related properties
        left_operand1 = constraint1['leftOperand']
        left_operand2 = constraint2['leftOperand']

        if left_operand1 != left_operand2 and not (self._is_included_in(left_operand1, left_operand2) or
                                                   self._is_included_in(left_operand2, left_operand1)):
            return False

        # Check if they use compatible operators
        operator1 = constraint1['operator'].split('/')[-1]  # Extract the last part of the URI
        operator2 = constraint2['operator'].split('/')[-1]  # Extract the last part of the URI

        if operator1 != operator2 and not self._are_operators_compatible(operator1, operator2):
            return False

        # Get the right operands
        right_operand1 = constraint1['rightOperand']
        right_operand2 = constraint2['rightOperand']

        # Check if right operands are URIs that could have included relationships
        if isinstance(right_operand1, str) and isinstance(right_operand2, str) and right_operand1.startswith('http'):
            if right_operand1 == right_operand2 or self._is_included_in(right_operand1,
                                                                        right_operand2) or self._is_included_in(
                    right_operand2, right_operand1):
                return True

        # Handle different operators
        if operator1 in ['eq', 'neq']:
            return right_operand1 == right_operand2

        # For numeric or datetime comparisons
        try:
            # If it's a dateTime, convert to a comparable format
            datatype1 = constraint1.get('datatype')
            datatype2 = constraint2.get('datatype')

            if (datatype1 and str(XSD.dateTime) in datatype1) or (datatype2 and str(XSD.dateTime) in datatype2):
                date1 = datetime.fromisoformat(right_operand1.replace('Z', '+00:00'))
                date2 = datetime.fromisoformat(right_operand2.replace('Z', '+00:00'))

                if operator1 == 'lt':
                    return date1 <= date2
                elif operator1 == 'lteq':
                    return date1 <= date2
                elif operator1 == 'gt':
                    return date1 >= date2
                elif operator1 == 'gteq':
                    return date1 >= date2
            else:
                # Try numeric comparison
                val1 = float(right_operand1)
                val2 = float(right_operand2)

                if operator1 == 'lt':
                    return val1 <= val2
                elif operator1 == 'lteq':
                    return val1 <= val2
                elif operator1 == 'gt':
                    return val1 >= val2
                elif operator1 == 'gteq':
                    return val1 >= val2
        except (ValueError, TypeError):
            # Not numeric or datetime values, just check equality
            return right_operand1 == right_operand2

        # Default case
        return False


    def _are_operators_compatible(self, op1, op2):
        """
        Check if two operators are compatible.

        Args:
            op1: First operator (string)
            op2: Second operator (string)

        Returns:
            bool: True if operators are compatible, False otherwise
        """
        # If they're the same, they're compatible
        if op1 == op2:
            return True

        # Compatible operator pairs
        compatible_pairs = [
            ('lt', 'lteq'),
            ('gt', 'gteq')
        ]

        return (op1, op2) in compatible_pairs or (op2, op1) in compatible_pairs


    def _rules_intersect(self, rule1, rule2):
        """
        Check if rule1 intersects with rule2.
        Rules intersect if they refer to the same action on intersecting targets
        with compatible constraints.

        Args:
            rule1: First ODRL rule (dictionary)
            rule2: Second ODRL rule (dictionary)

        Returns:
            bool: True if rules intersect, False otherwise
        """
        # Check if the actions are compatible
        if not self._actions_compatible(rule1['action'], rule2['action']):
            return False

        # Check if the targets intersect
        if not self._targets_intersect(rule1['target'], rule2['target']):
            return False

        # Check if the assignees intersect
        if rule1['assignee'] and rule2['assignee'] and not self._assignees_intersect(rule1['assignee'],
                                                                                     rule2['assignee']):
            return False

        # Check if the constraints are compatible
        if not self._constraints_compatible(rule1['constraint'], rule2['constraint']):
            return False

        # Check if the refinements are compatible
        if not self._constraints_compatible(rule1['refinement'], rule2['refinement']):
            return False

        return True


    def _targets_intersect(self, target1, target2):
        """
        Check if target1 intersects with target2.

        Args:
            target1: First ODRL target (dictionary)
            target2: Second ODRL target (dictionary)

        Returns:
            bool: True if targets intersect, False otherwise
        """
        # If either is None, we can't compare
        if target1 is None or target2 is None:
            return False

        # Check if they have the same value or if one is included in the other
        if target1['value'] == target2['value'] or self._is_included_in(target1['value'],
                                                                        target2['value']) or self._is_included_in(
                target2['value'], target1['value']):
            return True

        return False


    def _assignees_intersect(self, assignee1, assignee2):
        """
        Check if two assignees intersect.

        Args:
            assignee1: First assignee (dictionary)
            assignee2: Second assignee (dictionary)

        Returns:
            bool: True if assignees intersect, False otherwise
        """
        # If either is None, we consider them not intersecting
        if assignee1 is None or assignee2 is None:
            return False

        # Check if they have the same value or if one is included in the other
        if assignee1['value'] == assignee2['value'] or self._is_included_in(assignee1['value'],
                                                                            assignee2['value']) or self._is_included_in(
                assignee2['value'], assignee1['value']):
            return True

        return False


    def _constraints_compatible(self, constraints1, constraints2):
        """
        Check if two sets of constraints are compatible.

        Args:
            constraints1: List of constraints from first rule
            constraints2: List of constraints from second rule

        Returns:
            bool: True if constraints are compatible, False otherwise
        """
        # If either set is empty, they're compatible
        if not constraints1 or not constraints2:
            return True

        # Check if there's any pair of constraints that are incompatible
        for constraint1 in constraints1:
            for constraint2 in constraints2:
                if self._is_same_property(constraint1, constraint2) and not self._values_compatible(constraint1,
                                                                                                    constraint2):
                    return False

        return True


    def _is_same_property(self, constraint1, constraint2):
        """
        Check if two constraints refer to the same property or to related properties.

        Args:
            constraint1: First ODRL constraint (dictionary)
            constraint2: Second ODRL constraint (dictionary)

        Returns:
            bool: True if constraints refer to the same property, False otherwise
        """
        left_operand1 = constraint1['leftOperand']
        left_operand2 = constraint2['leftOperand']

        return left_operand1 == left_operand2 or self._is_included_in(left_operand1,
                                                                      left_operand2) or self._is_included_in(
            left_operand2, left_operand1)


    def _values_compatible(self, constraint1, constraint2):
        """
        Check if the values in two constraints are compatible.

        Args:
            constraint1: First ODRL constraint (dictionary)
            constraint2: Second ODRL constraint (dictionary)

        Returns:
            bool: True if values are compatible, False otherwise
        """
        # Get the operators and values
        operator1 = constraint1['operator'].split('/')[-1]  # Extract the last part of the URI
        operator2 = constraint2['operator'].split('/')[-1]  # Extract the last part of the URI
        value1 = constraint1['rightOperand']
        value2 = constraint2['rightOperand']

        # If values are URIs, check for included relationships
        if isinstance(value1, str) and isinstance(value2, str):
            # If both are URIs, check for included relationship
            if value1.startswith('http') and value2.startswith('http'):
                if value1 == value2 or self._is_included_in(value1, value2) or self._is_included_in(value2, value1):
                    return True

        # If operators are the same
        if operator1 == operator2:
            if operator1 in ['eq', 'neq']:
                return value1 == value2

            # For datetime or numeric values
            try:
                # Check if it's a dateTime
                datatype1 = constraint1.get('datatype')
                datatype2 = constraint2.get('datatype')

                if (datatype1 and str(XSD.dateTime) in datatype1) or (datatype2 and str(XSD.dateTime) in datatype2):
                    date1 = datetime.fromisoformat(value1.replace('Z', '+00:00'))
                    date2 = datetime.fromisoformat(value2.replace('Z', '+00:00'))

                    if operator1 == 'lt':
                        return date1 == date2
                    elif operator1 == 'lteq':
                        return date1 == date2
                    elif operator1 == 'gt':
                        return date1 == date2
                    elif operator1 == 'gteq':
                        return date1 == date2
                else:
                    # Try numeric comparison
                    val1 = float(value1)
                    val2 = float(value2)

                    if operator1 == 'lt':
                        return val1 == val2
                    elif operator1 == 'lteq':
                        return val1 == val2
                    elif operator1 == 'gt':
                        return val1 == val2
                    elif operator1 == 'gteq':
                        return val1 == val2
            except (ValueError, TypeError):
                # Not numeric or datetime values, just check equality
                return value1 == value2

        # If operators are different but can be compatible
        if self._are_operators_compatible(operator1, operator2):
            try:
                # Check if it's a dateTime
                datatype1 = constraint1.get('datatype')
                datatype2 = constraint2.get('datatype')

                if (datatype1 and str(XSD.dateTime) in datatype1) or (datatype2 and str(XSD.dateTime) in datatype2):
                    date1 = datetime.fromisoformat(value1.replace('Z', '+00:00'))
                    date2 = datetime.fromisoformat(value2.replace('Z', '+00:00'))

                    # Check if the ranges defined by the operators overlap
                    if (operator1 == 'lt' and operator2 == 'gt') or (operator1 == 'gt' and operator2 == 'lt'):
                        return date1 < date2 if operator1 == 'lt' else date1 > date2
                    elif (operator1 == 'lteq' and operator2 == 'gteq') or (operator1 == 'gteq' and operator2 == 'lteq'):
                        return date1 <= date2 if operator1 == 'lteq' else date1 >= date2
                else:
                    # Try numeric comparison
                    val1 = float(value1)
                    val2 = float(value2)

                    # Check if the ranges defined by the operators overlap
                    if (operator1 == 'lt' and operator2 == 'gt') or (operator1 == 'gt' and operator2 == 'lt'):
                        return val1 < val2 if operator1 == 'lt' else val1 > val2
                    elif (operator1 == 'lteq' and operator2 == 'gteq') or (operator1 == 'gteq' and operator2 == 'lteq'):
                        return val1 <= val2 if operator1 == 'lteq' else val1 >= val2
            except (ValueError, TypeError):
                # Not comparable values
                return False

        # Default case
        return False
# Example usage
def main():
    # Example ODRL policies in Turtle format
    owner_turtle = """
    @prefix odrl: <http://www.w3.org/ns/odrl/2/> .
    @prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
    @prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .
    @prefix dpv: <https://w3id.org/dpv/owl#> .

    <http://example.org/policy1> a odrl:Policy ;

      odrl:permission [
        odrl:target [
          a odrl:AssetCollection ;
          rdf:value <http://example.org/datasets/covid19Stats>
        ] ;
        odrl:action [
          rdf:value odrl:modify
        ] ;
        odrl:assignee [
          a odrl:PartyCollection ;
          rdf:value dpv:AcademicScientificOrganisation
        ] ;
        odrl:constraint [
          odrl:leftOperand odrl:purpose ;
          odrl:operator odrl:eq ;
          odrl:rightOperand <http://example.org/purpose/commercial>
        ]
      ] ;
      odrl:prohibition [
        odrl:target [
          a odrl:AssetCollection ;
          rdf:value <http://example.org/datasets/covid19Stats>
        ] ;
        odrl:action [
          rdf:value odrl:modify
        ] ;
        odrl:assignee [
          a odrl:PartyCollection ;
          rdf:value dpv:AcademicScientificOrganisation
        ] ;
        odrl:constraint [
          odrl:leftOperand odrl:purpose ;
          odrl:operator odrl:eq ;
          odrl:rightOperand <http://example.org/purpose/commercial>
        ]
      ] .
    """

    user_turtle = """
    @prefix odrl: <http://www.w3.org/ns/odrl/2/> .
    @prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
    @prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .

    <http://example.org/policy2> a odrl:Policy ;

      odrl:permission [
        odrl:target [
          a odrl:AssetCollection ;
          rdf:value <http://example.org/datasets/covid19Stats>
        ] ;
        odrl:action [
          rdf:value odrl:use ;
          odrl:refinement [
            odrl:leftOperand odrl:dateTime ;
            odrl:operator odrl:lt ;
            odrl:rightOperand "2025-12-31T23:59:59Z"^^xsd:dateTime
          ]
        ] ;
      ] .
    """

    # Create policy checker with ontology file
    checker = ODRLPolicyChecker(ontology_file="ontology/ODRL_DPV.rdf")

    # Check compatibility
    is_compatible, reason = checker.check_policy_compatibility(owner_turtle, user_turtle)
    print(f"Policies are {'compatible' if is_compatible else 'incompatible'}")
    print(f"Reason: {reason}")


if __name__ == "__main__":
    main()

