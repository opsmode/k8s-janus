#!/usr/bin/env python3
"""Generate values.schema.json from helm/values.yaml."""
import json
import sys
import yaml


def infer_schema(value):
    if isinstance(value, bool):
        return {"type": "boolean"}
    if isinstance(value, int):
        return {"type": "integer"}
    if isinstance(value, float):
        return {"type": "number"}
    if isinstance(value, str):
        return {"type": "string"}
    if isinstance(value, list):
        schema = {"type": "array"}
        if value:
            item_schemas = [infer_schema(i) for i in value]
            # If all items are same type, use it
            types = {s.get("type") for s in item_schemas}
            if len(types) == 1:
                schema["items"] = item_schemas[0]
            else:
                schema["items"] = {}
        return schema
    if isinstance(value, dict):
        schema = {"type": "object", "properties": {}}
        for k, v in value.items():
            schema["properties"][k] = infer_schema(v)
        return schema
    if value is None:
        return {}
    return {}


def main():
    values_path = "helm/values.yaml"
    schema_path = "helm/values.schema.json"

    with open(values_path) as f:
        values = yaml.safe_load(f)

    schema = infer_schema(values)
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["title"] = "K8s-Janus Helm Values"
    schema["description"] = "Helm values for K8s-Janus — Just-in-Time Kubernetes pod access"

    with open(schema_path, "w") as f:
        json.dump(schema, f, indent=2)
        f.write("\n")

    print(f"Generated {schema_path}")


if __name__ == "__main__":
    main()
