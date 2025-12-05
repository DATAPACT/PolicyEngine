// odrl_editor.js

document.addEventListener('DOMContentLoaded', function() {
    // Function to fill dropdown
    function fillDropdown(dropdownId, data) {
        var dropdown = document.getElementById(dropdownId);
        dropdown.innerHTML = '';
        data.forEach(function(item) {
            var option = document.createElement('option');
            option.value = item.uri;
            option.textContent = item.label;
            dropdown.appendChild(option);
        });
        dropdown.selectedIndex = -1;
    }

    // Function to add refinement row
    function addRefinementRow($form, entity, entityName, type, operator, value) {
        var container = $form.querySelector('#refinement' + entityName + 'Container');
        var template = container.querySelector('.refinement' + entityName + 'Row');
        var newRow = template.cloneNode(true);

        newRow.querySelector('.refinement' + entityName + 'Dropdown').value = type;
        newRow.querySelector('.operatorRefinement' + entityName + 'Dropdown').value = operator;
        newRow.querySelector('.refinement' + entityName + 'Value').value = value;

        newRow.style.display = 'flex';
        container.appendChild(newRow);
    }

    // Function to load JSON data
    function loadJsonData(data) {
        var template = document.querySelector('.form-card');
        var newForm = template.cloneNode(true);
        newForm.style.display = 'block';
        document.querySelector('.col-lg-12').appendChild(newForm);

        newForm.querySelector('#ruleDropdown').value = data.rule;
        newForm.querySelector('#ActorDropdown').value = data.actor;
        newForm.querySelector('#ActionDropdown').value = data.action;
        newForm.querySelector('#TargetDropdown').value = data.target;
        newForm.querySelector('#PurposeDropdown').value = data.purpose;
        newForm.querySelector('#queryTextbox').value = data.query;

        // Clear existing rows
        newForm.querySelectorAll('.constraintRow:not(:first-child)').forEach(e => e.remove());
        newForm.querySelectorAll('.refinementActorRow:not(:first-child)').forEach(e => e.remove());
        newForm.querySelectorAll('.refinementActionRow:not(:first-child)').forEach(e => e.remove());
        newForm.querySelectorAll('.refinementPurposeRow:not(:first-child)').forEach(e => e.remove());
        newForm.querySelectorAll('.refinementTargetRow:not(:first-child)').forEach(e => e.remove());

        if (Object.keys(data).length > 0) {
            // Load constraints
            data.constraints.forEach(function (constraint) {
                var newConstraintRow = newForm.querySelector('.constraintRow').cloneNode(true);
                newConstraintRow.querySelector('.constraintDropdown').value = constraint.type;
                newConstraintRow.querySelector('.operatorDropdown').value = constraint.operator;
                newConstraintRow.querySelector('.constraintValue').value = constraint.value;
                newForm.querySelector('#constraintsContainer').appendChild(newConstraintRow);
            });

            // Load refinements
            data.actorrefinements.forEach(r => addRefinementRow(newForm, data.actor, 'Actor', r.type, r.operator, r.value));
            data.actionrefinements.forEach(r => addRefinementRow(newForm, data.action, 'Action', r.type, r.operator, r.value));
            data.purposerefinements.forEach(r => addRefinementRow(newForm, data.purpose, 'Purpose', r.type, r.operator, r.value));
            data.targetrefinements.forEach(r => addRefinementRow(newForm, data.target, 'Target', r.type, r.operator, r.value));
        }
        applyFormActions(newForm);
    }

    // Function to apply form actions
    function applyFormActions(form) {
        form.querySelectorAll('.removeRow').forEach(button => {
            button.addEventListener('click', function() {
                this.closest('.constraintRow').remove();
            });
        });

        form.querySelector('.remove-form-button').addEventListener('click', function() {
            form.remove();
        });

        form.querySelector('#addConstraintRow').addEventListener('click', function() {
            var newRow = form.querySelector('.constraintRow').cloneNode(true);
            newRow.querySelectorAll('select, input').forEach(el => el.value = '');
            newRow.style.display = 'flex';
            form.querySelector('#constraintsContainer').appendChild(newRow);
            applyFormActions(newRow);
        });
    }

    // Event listener for save button
    document.getElementById('saveButton').addEventListener('click', function() {
        var saveddata = [];

        document.querySelectorAll('.form-card').forEach(function(form) {
            var data = {
                rule: form.querySelector('#ruleDropdown').value,
                actor: form.querySelector('#ActorDropdown').value,
                action: form.querySelector('#ActionDropdown').value,
                target: form.querySelector('#TargetDropdown').value,
                purpose: form.querySelector('#PurposeDropdown').value,
                query: form.querySelector('#queryTextbox').value,
                constraints: [],
                actorrefinements: [],
                actionrefinements: [],
                purposerefinements: [],
                targetrefinements: []
            };

            form.querySelectorAll('.constraintRow').forEach(function(row) {
                data.constraints.push({
                    type: row.querySelector('.constraintDropdown').value,
                    operator: row.querySelector('.operatorDropdown').value,
                    value: row.querySelector('.constraintValue').value
                });
            });

            // Gather refinements data (similar structure for actor, action, purpose, target)
            ['Actor', 'Action', 'Purpose', 'Target'].forEach(function(entity) {
                form.querySelectorAll('.refinement' + entity + 'Row').forEach(function(row) {
                    data[entity.toLowerCase() + 'refinements'].push({
                        type: row.querySelector('.refinement' + entity + 'Dropdown').value,
                        operator: row.querySelector('.operatorRefinement' + entity + 'Dropdown').value,
                        value: row.querySelector('.refinement' + entity + 'Value').value
                    });
                });
            });

            saveddata.push(data);
        });

        // AJAX request to save data
        fetch('/convert_to_odrl', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(saveddata)
        })
        .then(response => response.json())
        .then(result => {
            console.log(result);
            var formattedResult = JSON.stringify(result, null, 2).replace(/\\n/g, '\n').replace(/\\"/g, '"');
            document.getElementById('savedOdrl').value = formattedResult;
            exportFormattedResultToJSON(formattedResult);
        })
        .catch(error => {
            console.error('Error:', error);
        });
    });

    // Function to export formatted result to JSON
    function exportFormattedResultToJSON(formattedResult) {
        var blob = new Blob([formattedResult], { type: 'application/json' });
        var a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'odrl.json';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
    }

    // Event listener for file input
    document.getElementById('fileInput').addEventListener('change', function(event) {
        document.querySelectorAll('.form-card:not(:first-child)').forEach(e => e.remove());
        var reader = new FileReader();
        reader.onload = function() {
            try {
                var jsonData = JSON.parse(reader.result);
                if (typeof jsonData === 'string') {
                    jsonData = JSON.parse(jsonData);
                }
                if (typeof jsonData === 'object' && !Array.isArray(jsonData)) {
                    jsonData.data.forEach(function(data, index) {
                        setTimeout(function() {
                            loadJsonData(data);
                        }, index * 1000);
                    });
                } else {
                    alert('JSON data is not an object.');
                }
            } catch (error) {
                alert('Invalid JSON format.');
            }
        };
        reader.readAsText(event.target.files[0]);
    });

    // Event listeners for other buttons
    document.getElementById('uploadButton').addEventListener('click', function() {
        // Implementation for upload button
    });

    document.getElementById('newRuleButton').addEventListener('click', function() {
        loadJsonData({});
    });

    document.getElementById('clearButton').addEventListener('click', function() {
        // Implementation for clear button
    });

    // Initial setup
    fillDropdown('ruleDropdown', rules);
    fillDropdown('ActionDropdown', actions);
    fillDropdown('TargetDropdown', targets);
    fillDropdown('PurposeDropdown', purposes);
    fillDropdown('constraintDropdown', constraints);
    fillDropdown('operatorDropdown', operators);
    fillDropdown('ActorDropdown', actors);
});