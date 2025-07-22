# # Elasticsearch ML Index Field Mappings Extractor
# # This script extracts detailed field mappings for all ML anomaly indices

# $headers = @{Authorization="Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes('***REMOVED_EMAIL***:***REMOVED_PASSWORD***')))"}
# $baseUrl = "https://***REMOVED_INTERNAL_IP***:9200"

# # All ML Anomaly Indices discovered
# $allIndices = @(
#     # Linux Process Indices
#     ".ml-anomalies-custom-v3_linux_anomalous_process_all_hosts",
#     ".ml-anomalies-custom-v3_linux_rare_metadata_process", 
#     ".ml-anomalies-custom-v3_rare_process_by_host_linux",
    
#     # Linux Network Indices
#     ".ml-anomalies-custom-v3_linux_anomalous_network_activity",
#     ".ml-anomalies-custom-v3_linux_anomalous_network_port_activity",
#     ".ml-anomalies-custom-v3_linux_network_configuration_discovery",
#     ".ml-anomalies-custom-v3_linux_network_connection_discovery",
#     ".ml-anomalies-custom-high_count_network_denies",
#     ".ml-anomalies-custom-high_count_network_events",
    
#     # Linux User Indices
#     ".ml-anomalies-custom-v3_linux_anomalous_user_name",
#     ".ml-anomalies-custom-v3_linux_rare_metadata_user",
#     ".ml-anomalies-custom-v3_linux_rare_sudo_user",
#     ".ml-anomalies-custom-v3_linux_rare_user_compiler",
    
#     # Linux System Discovery Indices
#     ".ml-anomalies-custom-v3_linux_system_information_discovery",
#     ".ml-anomalies-custom-v3_linux_system_process_discovery",
#     ".ml-anomalies-custom-v3_linux_system_user_discovery",
    
#     # Windows Indices
#     ".ml-anomalies-custom-v3_windows_anomalous_process_all_hosts",
#     ".ml-anomalies-custom-v3_windows_anomalous_network_activity",
#     ".ml-anomalies-custom-v3_windows_anomalous_user_name",
#     ".ml-anomalies-custom-v3_windows_rare_user_runas_event", 
#     ".ml-anomalies-custom-v3_windows_rare_user_type10_remote_login",
    
#     # Authentication Indices
#     ".ml-anomalies-custom-suspicious_login_activity"
# )

# function Get-IndexFieldMapping($indexName) {
#     try {
#         Write-Host "`n" + ("="*80) -ForegroundColor Cyan
#         Write-Host "INDEX: $indexName" -ForegroundColor Yellow
#         Write-Host ("="*80) -ForegroundColor Cyan
        
#         # Get mapping
#         $mappingResponse = Invoke-WebRequest -Uri "$baseUrl/$indexName/_mapping" -Headers $headers -SkipCertificateCheck
#         $mapping = ($mappingResponse.Content | ConvertFrom-Json).$indexName.mappings.properties
        
#         # Get sample document with all fields
#         $sampleResponse = Invoke-WebRequest -Uri "$baseUrl/$indexName/_search?size=1&sort=timestamp:desc" -Headers $headers -SkipCertificateCheck
#         $sampleDoc = ($sampleResponse.Content | ConvertFrom-Json).hits.hits[0]._source
        
#         Write-Host "`n📋 FIELD MAPPINGS:" -ForegroundColor Green
        
#         # Core ML Fields
#         Write-Host "`n🔍 Core ML Fields:" -ForegroundColor Magenta
#         $coreFields = @("timestamp", "job_id", "result_type", "record_score", "initial_record_score", 
#                        "bucket_span", "detector_index", "function", "function_description", 
#                        "by_field_name", "by_field_value", "typical", "actual", "probability", 
#                        "anomaly_score", "initial_anomaly_score")
        
#         foreach ($field in $coreFields) {
#             if ($mapping.$field) {
#                 $fieldType = $mapping.$field.type
#                 $sampleValue = if ($sampleDoc.$field) { $sampleDoc.$field } else { "null" }
#                 Write-Host "  $field : $fieldType | Sample: $sampleValue"
#             }
#         }
        
#         # Entity Fields (Object Structure)
#         Write-Host "`n👤 Entity Fields:" -ForegroundColor Magenta
#         $entityFields = @("host", "process", "user", "destination", "source")
        
#         foreach ($field in $entityFields) {
#             if ($mapping.$field) {
#                 if ($mapping.$field.properties) {
#                     Write-Host "  $field : object"
#                     foreach ($subField in $mapping.$field.properties.PSObject.Properties) {
#                         $subFieldType = $subField.Value.type
#                         $sampleValue = if ($sampleDoc.$field.$($subField.Name)) { $sampleDoc.$field.$($subField.Name) } else { "null" }
#                         Write-Host "    $($subField.Name) : $subFieldType | Sample: $sampleValue"
#                     }
#                 } else {
#                     $fieldType = $mapping.$field.type
#                     $sampleValue = if ($sampleDoc.$field) { $sampleDoc.$field } else { "null" }
#                     Write-Host "  $field : $fieldType | Sample: $sampleValue"
#                 }
#             }
#         }
        
#         # Network Specific Fields
#         Write-Host "`n🌐 Network Fields:" -ForegroundColor Magenta
#         $networkFields = @("destination_ip", "source_ip", "destination_port", "source_port", 
#                           "network_protocol", "bytes_sent", "bytes_received", "network_name",
#                           "network_direction", "network_transport")
        
#         foreach ($field in $networkFields) {
#             if ($mapping.$field) {
#                 $fieldType = $mapping.$field.type
#                 $sampleValue = if ($sampleDoc.$field) { $sampleDoc.$field } else { "null" }
#                 Write-Host "  $field : $fieldType | Sample: $sampleValue"
#             }
#         }
        
#         # Process Specific Fields
#         Write-Host "`n⚙️ Process Fields:" -ForegroundColor Magenta
#         $processFields = @("process_id", "parent_process", "command_line", "file_path", 
#                           "process_name", "process_title", "process_executable")
        
#         foreach ($field in $processFields) {
#             if ($mapping.$field) {
#                 if ($mapping.$field.properties) {
#                     Write-Host "  $field : object"
#                     foreach ($subField in $mapping.$field.properties.PSObject.Properties) {
#                         $subFieldType = $subField.Value.type
#                         $sampleValue = if ($sampleDoc.$field.$($subField.Name)) { $sampleDoc.$field.$($subField.Name) } else { "null" }
#                         Write-Host "    $($subField.Name) : $subFieldType | Sample: $sampleValue"
#                     }
#                 } else {
#                     $fieldType = $mapping.$field.type
#                     $sampleValue = if ($sampleDoc.$field) { $sampleDoc.$field } else { "null" }
#                     Write-Host "  $field : $fieldType | Sample: $sampleValue"
#                 }
#             }
#         }
        
#         # Authentication/User Fields
#         Write-Host "`n🔐 Authentication Fields:" -ForegroundColor Magenta
#         $authFields = @("user_name", "login_type", "source_address", "target_user", 
#                        "logon_type", "authentication_method", "session_id")
        
#         foreach ($field in $authFields) {
#             if ($mapping.$field) {
#                 $fieldType = $mapping.$field.type
#                 $sampleValue = if ($sampleDoc.$field) { $sampleDoc.$field } else { "null" }
#                 Write-Host "  $field : $fieldType | Sample: $sampleValue"
#             }
#         }
        
#         # ML Nested Arrays
#         Write-Host "`n📊 ML Nested Arrays:" -ForegroundColor Magenta
#         $nestedFields = @("causes", "influencers", "bucket_influencers")
        
#         foreach ($field in $nestedFields) {
#             if ($mapping.$field) {
#                 Write-Host "  $field : nested array"
#                 if ($mapping.$field.properties) {
#                     foreach ($subField in $mapping.$field.properties.PSObject.Properties) {
#                         $subFieldType = $subField.Value.type
#                         Write-Host "    $($subField.Name) : $subFieldType"
#                     }
#                 }
#             }
#         }
        
#         # Other Specific Fields
#         Write-Host "`n🏷️ Other Index-Specific Fields:" -ForegroundColor Magenta
#         $otherFields = @("event_count", "model_feature", "model_lower", "model_upper", 
#                         "model_median", "multi_bucket_impact", "field_name", "over_field_name",
#                         "over_field_value", "partition_field_name", "partition_field_value",
#                         "is_interim", "raw_anomaly_score", "influencer_score")
        
#         foreach ($field in $otherFields) {
#             if ($mapping.$field) {
#                 $fieldType = $mapping.$field.type
#                 $sampleValue = if ($sampleDoc.$field) { $sampleDoc.$field } else { "null" }
#                 Write-Host "  $field : $fieldType | Sample: $sampleValue"
#             }
#         }
        
#         # Custom/Unknown Fields
#         Write-Host "`n🔧 All Other Fields:" -ForegroundColor Magenta
#         $knownFields = $coreFields + $entityFields + $networkFields + $processFields + $authFields + $nestedFields + $otherFields
        
#         foreach ($field in $mapping.PSObject.Properties) {
#             if ($field.Name -notin $knownFields) {
#                 $fieldType = $field.Value.type
#                 if (-not $fieldType) { $fieldType = "object/nested" }
#                 $sampleValue = if ($sampleDoc.$($field.Name)) { $sampleDoc.$($field.Name) } else { "null" }
#                 Write-Host "  $($field.Name) : $fieldType | Sample: $sampleValue"
#             }
#         }
        
#         # Document Count
#         $countResponse = Invoke-WebRequest -Uri "$baseUrl/$indexName/_count" -Headers $headers -SkipCertificateCheck
#         $docCount = ($countResponse.Content | ConvertFrom-Json).count
#         Write-Host "`n📈 Document Count: $docCount" -ForegroundColor Green
        
#     }
#     catch {
#         Write-Host "`n❌ Error processing $indexName : $($_.Exception.Message)" -ForegroundColor Red
#     }
# }

# # Process all indices
# Write-Host "🚀 Starting ML Index Field Mapping Extraction..." -ForegroundColor Green
# Write-Host "📋 Processing $($allIndices.Count) indices..." -ForegroundColor Yellow

# foreach ($index in $allIndices) {
#     Get-IndexFieldMapping $index
#     Start-Sleep -Milliseconds 500  # Rate limiting
# }

# Write-Host "`n✅ Field mapping extraction complete!" -ForegroundColor Green
# Write-Host "💾 Save this output to reference when structuring your ML model data." -ForegroundColor Cyan

# # Generate summary
# Write-Host "`n" + ("="*80) -ForegroundColor Yellow
# Write-Host "📋 SUMMARY OF AVAILABLE INDICES" -ForegroundColor Yellow
# Write-Host ("="*80) -ForegroundColor Yellow

# Write-Host "`n🐧 Linux Process Indices (3):"
# Write-Host "  - .ml-anomalies-custom-v3_linux_anomalous_process_all_hosts"
# Write-Host "  - .ml-anomalies-custom-v3_linux_rare_metadata_process"
# Write-Host "  - .ml-anomalies-custom-v3_rare_process_by_host_linux"

# Write-Host "`n🌐 Linux Network Indices (6):"
# Write-Host "  - .ml-anomalies-custom-v3_linux_anomalous_network_activity"
# Write-Host "  - .ml-anomalies-custom-v3_linux_anomalous_network_port_activity" 
# Write-Host "  - .ml-anomalies-custom-v3_linux_network_configuration_discovery"
# Write-Host "  - .ml-anomalies-custom-v3_linux_network_connection_discovery"
# Write-Host "  - .ml-anomalies-custom-high_count_network_denies"
# Write-Host "  - .ml-anomalies-custom-high_count_network_events"

# Write-Host "`n👤 Linux User Indices (4):"
# Write-Host "  - .ml-anomalies-custom-v3_linux_anomalous_user_name"
# Write-Host "  - .ml-anomalies-custom-v3_linux_rare_metadata_user"
# Write-Host "  - .ml-anomalies-custom-v3_linux_rare_sudo_user"
# Write-Host "  - .ml-anomalies-custom-v3_linux_rare_user_compiler"

# Write-Host "`n🔍 Linux System Discovery Indices (3):"
# Write-Host "  - .ml-anomalies-custom-v3_linux_system_information_discovery"
# Write-Host "  - .ml-anomalies-custom-v3_linux_system_process_discovery"
# Write-Host "  - .ml-anomalies-custom-v3_linux_system_user_discovery"

# Write-Host "`n💻 Windows Indices (5):"
# Write-Host "  - .ml-anomalies-custom-v3_windows_anomalous_process_all_hosts"
# Write-Host "  - .ml-anomalies-custom-v3_windows_anomalous_network_activity"
# Write-Host "  - .ml-anomalies-custom-v3_windows_anomalous_user_name"
# Write-Host "  - .ml-anomalies-custom-v3_windows_rare_user_runas_event"
# Write-Host "  - .ml-anomalies-custom-v3_windows_rare_user_type10_remote_login"

# Write-Host "`n🔐 Authentication Indices (1):"
# Write-Host "  - .ml-anomalies-custom-suspicious_login_activity"

# Write-Host "`n📊 Total: $($allIndices.Count) ML Anomaly Indices Available" -ForegroundColor Green

# Elasticsearch ML Index Field Mappings Extractor
# This script extracts detailed field mappings for all ML anomaly indices and saves to JSON

$headers = @{Authorization="Basic $([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes('***REMOVED_EMAIL***:***REMOVED_PASSWORD***')))"}
$baseUrl = "https://***REMOVED_INTERNAL_IP***:9200"
$outputFile = ".\elasticsearch_ml_mappings.json"

# All ML Anomaly Indices discovered
$allIndices = @(
    # Linux Process Indices
    ".ml-anomalies-custom-v3_linux_anomalous_process_all_hosts",
    ".ml-anomalies-custom-v3_linux_rare_metadata_process", 
    ".ml-anomalies-custom-v3_rare_process_by_host_linux",
    
    # Linux Network Indices
    ".ml-anomalies-custom-v3_linux_anomalous_network_activity",
    ".ml-anomalies-custom-v3_linux_anomalous_network_port_activity",
    ".ml-anomalies-custom-v3_linux_network_configuration_discovery",
    ".ml-anomalies-custom-v3_linux_network_connection_discovery",
    ".ml-anomalies-custom-high_count_network_denies",
    ".ml-anomalies-custom-high_count_network_events"
    
    # # Linux User Indices
    # ".ml-anomalies-custom-v3_linux_anomalous_user_name",
    # ".ml-anomalies-custom-v3_linux_rare_metadata_user",
    # ".ml-anomalies-custom-v3_linux_rare_sudo_user",
    # ".ml-anomalies-custom-v3_linux_rare_user_compiler",
    
    # # Linux System Discovery Indices
    # ".ml-anomalies-custom-v3_linux_system_information_discovery",
    # ".ml-anomalies-custom-v3_linux_system_process_discovery",
    # ".ml-anomalies-custom-v3_linux_system_user_discovery"
    
)

# Create an object to store all index information
$allIndexData = @{}

function Get-IndexFieldMapping($indexName) {
    try {
        Write-Host "Processing index: $indexName" -ForegroundColor Yellow
        
        # Get mapping
        $mappingResponse = Invoke-WebRequest -Uri "$baseUrl/$indexName/_mapping" -Headers $headers -SkipCertificateCheck
        $mapping = ($mappingResponse.Content | ConvertFrom-Json).$indexName.mappings.properties
        
        # Get sample document with all fields
        $sampleResponse = Invoke-WebRequest -Uri "$baseUrl/$indexName/_search?size=1&sort=timestamp:desc" -Headers $headers -SkipCertificateCheck
        $sampleDoc = ($sampleResponse.Content | ConvertFrom-Json).hits.hits[0]._source
        
        # Get document count
        $countResponse = Invoke-WebRequest -Uri "$baseUrl/$indexName/_count" -Headers $headers -SkipCertificateCheck
        $docCount = ($countResponse.Content | ConvertFrom-Json).count
        
        # Create structured data for this index
        $indexData = @{
            name = $indexName
            doc_count = $docCount
            field_mappings = @{}
            sample_document = $sampleDoc
            field_categories = @{
                core_ml_fields = @{}
                entity_fields = @{}
                network_fields = @{}
                process_fields = @{}
                authentication_fields = @{}
                ml_nested_arrays = @{}
                other_fields = @{}
                custom_fields = @{}
            }
        }
        
        # Core ML Fields
        $coreFields = @("timestamp", "job_id", "result_type", "record_score", "initial_record_score", 
                       "bucket_span", "detector_index", "function", "function_description", 
                       "by_field_name", "by_field_value", "typical", "actual", "probability", 
                       "anomaly_score", "initial_anomaly_score")
        
        foreach ($field in $coreFields) {
            if ($mapping.$field) {
                $fieldType = $mapping.$field.type
                $sampleValue = if ($sampleDoc.$field) { $sampleDoc.$field } else { $null }
                $indexData.field_mappings[$field] = @{
                    type = $fieldType
                    sample = $sampleValue
                }
                $indexData.field_categories.core_ml_fields[$field] = @{
                    type = $fieldType
                    sample = $sampleValue
                }
            }
        }
        
        # Entity Fields (Object Structure)
        $entityFields = @("host", "process", "user", "destination", "source")
        
        foreach ($field in $entityFields) {
            if ($mapping.$field) {
                if ($mapping.$field.properties) {
                    $subFields = @{}
                    foreach ($subField in $mapping.$field.properties.PSObject.Properties) {
                        $subFieldType = $subField.Value.type
                        $sampleValue = if ($sampleDoc.$field.$($subField.Name)) { $sampleDoc.$field.$($subField.Name) } else { $null }
                        $subFields[$subField.Name] = @{
                            type = $subFieldType
                            sample = $sampleValue
                        }
                    }
                    $indexData.field_mappings[$field] = @{
                        type = "object"
                        properties = $subFields
                    }
                    $indexData.field_categories.entity_fields[$field] = @{
                        type = "object"
                        properties = $subFields
                    }
                } else {
                    $fieldType = $mapping.$field.type
                    $sampleValue = if ($sampleDoc.$field) { $sampleDoc.$field } else { $null }
                    $indexData.field_mappings[$field] = @{
                        type = $fieldType
                        sample = $sampleValue
                    }
                    $indexData.field_categories.entity_fields[$field] = @{
                        type = $fieldType
                        sample = $sampleValue
                    }
                }
            }
        }
        
        # Network Specific Fields
        $networkFields = @("destination_ip", "source_ip", "destination_port", "source_port", 
                          "network_protocol", "bytes_sent", "bytes_received", "network_name",
                          "network_direction", "network_transport")
        
        foreach ($field in $networkFields) {
            if ($mapping.$field) {
                $fieldType = $mapping.$field.type
                $sampleValue = if ($sampleDoc.$field) { $sampleDoc.$field } else { $null }
                $indexData.field_mappings[$field] = @{
                    type = $fieldType
                    sample = $sampleValue
                }
                $indexData.field_categories.network_fields[$field] = @{
                    type = $fieldType
                    sample = $sampleValue
                }
            }
        }
        
        # Process Specific Fields
        $processFields = @("process_id", "parent_process", "command_line", "file_path", 
                          "process_name", "process_title", "process_executable")
        
        foreach ($field in $processFields) {
            if ($mapping.$field) {
                if ($mapping.$field.properties) {
                    $subFields = @{}
                    foreach ($subField in $mapping.$field.properties.PSObject.Properties) {
                        $subFieldType = $subField.Value.type
                        $sampleValue = if ($sampleDoc.$field.$($subField.Name)) { $sampleDoc.$field.$($subField.Name) } else { $null }
                        $subFields[$subField.Name] = @{
                            type = $subFieldType
                            sample = $sampleValue
                        }
                    }
                    $indexData.field_mappings[$field] = @{
                        type = "object"
                        properties = $subFields
                    }
                    $indexData.field_categories.process_fields[$field] = @{
                        type = "object"
                        properties = $subFields
                    }
                } else {
                    $fieldType = $mapping.$field.type
                    $sampleValue = if ($sampleDoc.$field) { $sampleDoc.$field } else { $null }
                    $indexData.field_mappings[$field] = @{
                        type = $fieldType
                        sample = $sampleValue
                    }
                    $indexData.field_categories.process_fields[$field] = @{
                        type = $fieldType
                        sample = $sampleValue
                    }
                }
            }
        }
        
        # Authentication/User Fields
        $authFields = @("user_name", "login_type", "source_address", "target_user", 
                       "logon_type", "authentication_method", "session_id")
        
        foreach ($field in $authFields) {
            if ($mapping.$field) {
                $fieldType = $mapping.$field.type
                $sampleValue = if ($sampleDoc.$field) { $sampleDoc.$field } else { $null }
                $indexData.field_mappings[$field] = @{
                    type = $fieldType
                    sample = $sampleValue
                }
                $indexData.field_categories.authentication_fields[$field] = @{
                    type = $fieldType
                    sample = $sampleValue
                }
            }
        }
        
        # ML Nested Arrays
        $nestedFields = @("causes", "influencers", "bucket_influencers")
        
        foreach ($field in $nestedFields) {
            if ($mapping.$field) {
                if ($mapping.$field.properties) {
                    $subFields = @{}
                    foreach ($subField in $mapping.$field.properties.PSObject.Properties) {
                        $subFieldType = $subField.Value.type
                        $subFields[$subField.Name] = @{
                            type = $subFieldType
                        }
                    }
                    $indexData.field_mappings[$field] = @{
                        type = "nested array"
                        properties = $subFields
                    }
                    $indexData.field_categories.ml_nested_arrays[$field] = @{
                        type = "nested array"
                        properties = $subFields
                    }
                } else {
                    $indexData.field_mappings[$field] = @{
                        type = "nested array"
                    }
                    $indexData.field_categories.ml_nested_arrays[$field] = @{
                        type = "nested array"
                    }
                }
            }
        }
        
        # Other Specific Fields
        $otherFields = @("event_count", "model_feature", "model_lower", "model_upper", 
                        "model_median", "multi_bucket_impact", "field_name", "over_field_name",
                        "over_field_value", "partition_field_name", "partition_field_value",
                        "is_interim", "raw_anomaly_score", "influencer_score")
        
        foreach ($field in $otherFields) {
            if ($mapping.$field) {
                $fieldType = $mapping.$field.type
                $sampleValue = if ($sampleDoc.$field) { $sampleDoc.$field } else { $null }
                $indexData.field_mappings[$field] = @{
                    type = $fieldType
                    sample = $sampleValue
                }
                $indexData.field_categories.other_fields[$field] = @{
                    type = $fieldType
                    sample = $sampleValue
                }
            }
        }
        
        # Custom/Unknown Fields
        $knownFields = $coreFields + $entityFields + $networkFields + $processFields + $authFields + $nestedFields + $otherFields
        
        foreach ($field in $mapping.PSObject.Properties) {
            if ($field.Name -notin $knownFields) {
                $fieldType = $field.Value.type
                if (-not $fieldType) { $fieldType = "object/nested" }
                $sampleValue = if ($sampleDoc.$($field.Name)) { $sampleDoc.$($field.Name) } else { $null }
                $indexData.field_mappings[$field.Name] = @{
                    type = $fieldType
                    sample = $sampleValue
                }
                $indexData.field_categories.custom_fields[$field.Name] = @{
                    type = $fieldType
                    sample = $sampleValue
                }
            }
        }
        
        # Add this index data to the collection
        $allIndexData[$indexName] = $indexData
        
        return $indexData
    }
    catch {
        Write-Host "Error processing $indexName : $($_.Exception.Message)" -ForegroundColor Red
        return @{
            name = $indexName
            error = $_.Exception.Message
        }
    }
}

# Process all indices
Write-Host "Starting ML Index Field Mapping Extraction..." -ForegroundColor Green
Write-Host "Processing $($allIndices.Count) indices..." -ForegroundColor Yellow

# Add index categories to the JSON structure
$jsonOutput = @{
    extraction_date = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    indices_count = $allIndices.Count
    categories = @{
        linux_process = $allIndices | Where-Object { $_ -like "*linux*" -and ($_ -like "*process*" -or $_ -like "*metadata_process*") }
        linux_network = $allIndices | Where-Object { $_ -like "*linux*" -and ($_ -like "*network*") }
        linux_user = $allIndices | Where-Object { $_ -like "*linux*" -and ($_ -like "*user*" -and $_ -notlike "*system_user*") }
        linux_system = $allIndices | Where-Object { $_ -like "*linux*" -and $_ -like "*system*" }
        windows = $allIndices | Where-Object { $_ -like "*windows*" }
        authentication = $allIndices | Where-Object { $_ -like "*login*" -or $_ -like "*authentication*" }
    }
    indices = @{}
}

foreach ($index in $allIndices) {
    $indexData = Get-IndexFieldMapping $index
    $jsonOutput.indices[$index] = $indexData
    Start-Sleep -Milliseconds 500  # Rate limiting
}

# Save to JSON file
$jsonOutput | ConvertTo-Json -Depth 10 | Out-File -FilePath $outputFile

Write-Host "Field mapping extraction complete!" -ForegroundColor Green
Write-Host "Data saved to: $outputFile" -ForegroundColor Cyan