# Policy Management API

This API allows for managing policies related to datasets and scripts using ODRL (Open Digital Rights Language) and DPV (Data Privacy Vocabulary). It provides endpoints for creating, retrieving, updating, deleting, and comparing policies for data providers and consumers. 

## Features

- Store and manage data provider and consumer policies.
- Validate and compare request policies against existing policies using RDF and SPARQL.
- Provides conflict detection between policies using ODRL.

## Requirements

- Python 3.8+
- FastAPI
- Motor (for MongoDB interaction)
- RDFLib (for policy handling with RDF)
- Jinja2 (for templates)

## Setup

### Clone the repository
```bash
git clone <repository_url>
cd <repository_folder>
```

### Install dependencies
```bash
pip install -r requirements.txt
```

### Set up MongoDB connection

Update your MongoDB connection details in `config.py`:
```python
# config.py
user = "your_mongodb_user"
password = "your_mongodb_password"
host = "your_mongodb_host"
```

Hint: You may create a free mongodb database in mongodb cloud.

### Run the API

To run the FastAPI application:

```bash
uvicorn api:app --reload
```

The API will be available at `http://localhost:8000`.

## API Endpoints

### Get Data Provider Policy
- **Endpoint:** `/get_data_provider_policy/{dataset_id}`
- **Method:** GET
- **Description:** Retrieve a policy for a specific dataset.
- **Response:**
    ```json
    {
      "odrl_policy": { ... }
    }
    ```

### Set Data Provider Policy
- **Endpoint:** `/set_data_provider_policy/{dataset_id}`
- **Method:** POST
- **Description:** Create or update a data provider policy for a dataset.
- **Payload Example:**
    ```json
    {
      "odrl_policy": { ... }
    }
    ```

### Remove Data Provider Policy
- **Endpoint:** `/remove_data_provider_policy/{dataset_id}`
- **Method:** DELETE
- **Description:** Remove a data provider policy for a dataset.

### Get Data Consumer Policy
- **Endpoint:** `/get_data_consumer_policy/{script_id}`
- **Method:** GET
- **Description:** Retrieve a policy for a specific script.
- **Response:**
    ```json
    {
      "odrl_policy": { ... }
    }
    ```

### Set Data Consumer Policy
- **Endpoint:** `/set_data_consumer_policy/{script_id}`
- **Method:** POST
- **Description:** Create or update a data consumer policy for a script.
- **Payload Example:**
    ```json
    {
      "odrl_policy": { ... }
    }
    ```

### Remove Data Consumer Policy
- **Endpoint:** `/remove_data_consumer_policy/{script_id}`
- **Method:** DELETE
- **Description:** Remove a data consumer policy for a script.

### Compare Policies
- **Endpoint:** `/compare_policies`
- **Method:** POST
- **Description:** Compare a script's request policy with an existing dataset policy to check for conflicts.
- **Payload Example:**
    ```json
    {
      "dataset_id": "example_dataset_id",
      "script_id": "example_script_id"
    }
    ```
- **Response:**
    ```json
    {
      "conflict_details": "No conflicts" | { "conflict_details": { ... } }
    }
    ```

## Policy Structure

Policies are stored and compared using ODRL, which represents permissions, prohibitions, and obligations using RDF.

- **Example Permission Policy:**
    ```json
    {
      "permission": [ ... ],
      "uid": "http://example.org/policy-79f7e6ba-daff-4919-940f-a1ad1344a97b",
      "@context": "http://www.w3.org/ns/odrl.jsonld",
      "@type": "http://www.w3.org/ns/odrl/2/Policy"
    }
    ```

- **Example Prohibition Policy:**
    ```json
    {
      "prohibition": [ ... ],
      "uid": "http://example.org/policy-79f7e6ba-daff-4919-940f-a1ad1344a97a",
      "@context": "http://www.w3.org/ns/odrl.jsonld",
      "@type": "http://www.w3.org/ns/odrl/2/Policy"
    }
    ```

## Development

To contribute to this project, feel free to submit pull requests. Make sure to test your changes thoroughly.

## License

This project is licensed under the MIT License.
