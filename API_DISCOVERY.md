# Cycode API Discovery - In-App Documentation Found

## 🎯 Breakthrough: Tenant-Specific API Documentation

**URL**: [https://app.cycode.com/in-app-api-docs?tenantId=05b4459c-7acb-46e7-b6b0-26717311cfa1](https://app.cycode.com/in-app-api-docs?tenantId=05b4459c-7acb-46e7-b6b0-26717311cfa1)

This is a **major discovery** - Cycode has tenant-specific API documentation that likely contains the policy management endpoints we need!

## What This Means

### ✅ **High Probability of Success**
- Tenant-specific API docs typically contain **full endpoint documentation**
- Policy management is likely documented here (not in public docs)
- Authentication methods will be clearly specified
- Actual API schemas and examples should be available

### 🔍 **Next Steps for You**

Since this requires authentication with your specific tenant, you'll need to:

1. **Access the Documentation**:
   ```
   1. Log into your Cycode account
   2. Navigate to: https://app.cycode.com/in-app-api-docs?tenantId=05b4459c-7acb-46e7-b6b0-26717311cfa1
   3. Look for policy-related endpoints
   ```

2. **Key Endpoints to Look For**:
   - `GET /api/v1/policies` or similar (list policies)
   - `GET /api/v1/policies/sast` (SAST-specific policies)
   - `PATCH /api/v1/policies/{id}` (update policy state)
   - `PUT /api/v1/policies/{id}/enable` (enable policy)
   - `PUT /api/v1/policies/{id}/disable` (disable policy)

3. **Authentication Details**:
   - Look for API token generation
   - Client ID/Secret usage examples
   - Bearer token format
   - Required headers

## What to Document

Please capture from the in-app API docs:

### 🔑 **Authentication**
```
- How to generate API tokens
- Required headers (Authorization, Content-Type, etc.)
- Token expiration and refresh
```

### 📋 **Policy Endpoints**
```
- List policies endpoint and response format
- Update policy state endpoint
- Required request body format
- Policy ID format and how to obtain them
```

### 📊 **Response Formats**
```
- Policy object structure
- Error response formats
- Status codes and meanings
```

## Updating Our Implementation

Once you have the endpoint details, we can update our `cycode_policy_sync.py` script with:

1. **Correct API endpoints**
2. **Proper authentication flow**
3. **Accurate request/response handling**
4. **Real policy ID mapping**

## Expected Outcome

With the in-app API documentation, we should be able to:

✅ **Confirm policy management is possible**  
✅ **Get exact endpoint URLs and methods**  
✅ **Understand authentication requirements**  
✅ **Complete the implementation**  
✅ **Test with real policy state changes**  

## Template for Information Gathering

When you access the docs, please look for:

```yaml
# Authentication
auth_method: "Bearer token" | "API Key" | "OAuth2"
token_endpoint: "/auth/token"
required_headers: 
  - "Authorization: Bearer {token}"
  - "Content-Type: application/json"

# Policy Endpoints
list_policies: 
  method: "GET"
  url: "/api/v1/policies/sast"
  response_format: "array of policy objects"

update_policy:
  method: "PATCH" | "PUT"
  url: "/api/v1/policies/{policy_id}"
  body_format: '{"enabled": true/false}'

# Policy Object Structure
policy_object:
  id: "string"
  name: "string" 
  enabled: boolean
  category: "SAST"
  # ... other fields
```

This discovery significantly increases the likelihood that **your GitOps SAST policy management approach is fully feasible**!
