use arrow::datatypes::{DataType, Field, Schema};

pub fn ports_schema() -> Schema {
    Schema::new(vec![
        Field::new("port_id", DataType::Int64, false),
        Field::new("host_id", DataType::Int64, false),
        Field::new("transport", DataType::Utf8, false),
        Field::new("port", DataType::Int64, false),
        Field::new("state", DataType::Utf8, false),
        Field::new("reason", DataType::Utf8, true),
        Field::new("service_name", DataType::Utf8, true),
        Field::new("confidence", DataType::Float64, false),
        Field::new("first_seen_ms", DataType::Int64, false),
        Field::new("last_seen_ms", DataType::Int64, false),
    ])
}

pub fn http_endpoints_schema() -> Schema {
    Schema::new(vec![
        Field::new("http_id", DataType::Int64, false),
        Field::new("port_id", DataType::Int64, false),
        Field::new("scheme", DataType::Utf8, false),
        Field::new("authority", DataType::Utf8, false),
        Field::new("path", DataType::Utf8, false),
        Field::new("status", DataType::Int64, true),
        Field::new("h2", DataType::Int64, false),
        Field::new("server_header", DataType::Utf8, true),
        Field::new("content_type", DataType::Utf8, true),
        Field::new("favicon_hash", DataType::Utf8, true),
        Field::new("tech_tags_json", DataType::Utf8, true),
        Field::new("tls_ja3", DataType::Utf8, true),
        Field::new("tls_ja3s", DataType::Utf8, true),
        Field::new("tls_chain_json", DataType::Utf8, true),
        Field::new("collected_ms", DataType::Int64, false),
    ])
}

