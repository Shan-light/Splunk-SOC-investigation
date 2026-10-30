
# Splunk SOC Investigation — Brute-Force Attack & Potential Compromise

## 1. Project Overview

### Objective

Use Splunk to investigate authentication logs, identify suspicious login patterns, correlate failed login attempts with a user account and source IP address, and assess whether the activity indicates a potential account compromise.

### Environment and Dataset

| Item | Details |
|---|---|
| Tool | Splunk Enterprise |
| Index | `splunk_soc` |
| Dataset | 40 security events |
| Data format | CSV |
| Investigation date in dataset | September 1, 2026 |
| Focus | SSH authentication failures, successful login activity, and post-login commands |

### Investigation Workflow

1. Ingest the log file into Splunk.
2. Verify data ingestion and important fields.
3. Establish a baseline for login activity.
4. Identify users and source IPs associated with failed logins.
5. Correlate the suspicious user and source IP.
6. Examine individual authentication events.
7. Investigate activity from the suspicious source IP.
8. Confirm whether authentication subsequently succeeded.
9. Document findings and recommend response actions.

---

## 2. Data Ingestion and Verification

### 2.1 Ingest the CSV Log File

The CSV log file was uploaded into Splunk Enterprise and assigned to the `splunk_soc` index. After ingestion, the data was reviewed to confirm that Splunk recognized the file and exposed the relevant event fields.

**Screenshot 1 — CSV Data Ingestion and Index Configuration**

![CSV Data Ingestion and Index Configuration](https://github.com/Shan-light/Splunk-SOC-investigation/blob/5e3fe47e4063cf994dfa98b46774988d0e871770/image/cvs%20data%20ingesting.png)

*Shows the uploaded file's source type, file type, host, and assigned index.*

### 2.2 Verify the Total Number of Events

**SPL query:**

```spl
index=splunk_soc
| stats count
```

**Result:** Splunk returned 40 events, confirming that the dataset was available in the `splunk_soc` index.

**Screenshot 2 — Verification of Total Ingested Events**

![Verification of Total Ingested Events](https://github.com/Shan-light/Splunk-SOC-investigation/blob/5e3fe47e4063cf994dfa98b46774988d0e871770/image/Verification%20Ingested%20Events%20.png)

### 2.3 Verify the Event Time Range

**SPL query:**

```spl
index=splunk_soc
| stats earliest(timestamp) as earliest latest(timestamp) as latest
```

**Results:**

- Earliest event: `2026-09-01 08:02:14`
- Latest event: `2026-09-01 14:56:21`

These timestamps establish the time range represented by the dataset's `timestamp` field.

**Screenshot 3 — Verification of Earliest and Latest Event Timestamps**

![Event Time Range](https://github.com/Shan-light/Splunk-SOC-investigation/blob/5e3fe47e4063cf994dfa98b46774988d0e871770/image/Verify%20the%20event%20time%20range.png)

### 2.4 Verify the Source Type

**SPL query:**

```spl
index=splunk_soc
| stats count by sourcetype
```

**Result:** The events were identified under the `CSV` source type.

**Screenshot 4 — Verification of Event Source Type**

![Event Source Type](https://github.com/Shan-light/Splunk-SOC-investigation/blob/5e3fe47e4063cf994dfa98b46774988d0e871770/image/Verify%20the%20source%20type.png)

### 2.5 Examine Host and User Fields

The initial host analysis showed that the owner's name had been ingested as the `host` value. I then reviewed the `extracted_host` and `user` fields together to examine the host information represented in the event data.

**Initial host check:**

```spl
index=splunk_soc
| stats count by host
| sort - count
```

**Host and user comparison:**

```spl
index=splunk_soc
| stats count by extracted_host user
| sort - count
```

**Screenshot 5 — Host and User Field Analysis**

![Host and User Field Analysis](https://github.com/Shan-light/Splunk-SOC-investigation/blob/5e3fe47e4063cf994dfa98b46774988d0e871770/image/Host%20and%20User%20Field%20Analysis.png)

### 2.6 Review Important Event Fields

**SPL query:**

```spl
index=splunk_soc
| table timestamp extracted_host user service action status src_ip dest_ip details
| sort timestamp
```

This search displayed the main fields required for the investigation, including timestamps, host, user, service, action, status, source IP, destination IP, and event details.

**Screenshot 6 — Review of Key Security Event Fields**

![Key Security Event Fields](https://github.com/Shan-light/Splunk-SOC-investigation/blob/5e3fe47e4063cf994dfa98b46774988d0e871770/image/Review%20of%20Key%20Security%20Event%20Fields.png)

---

## 3. Phase 2 — Splunk SOC Investigation

The goal of this phase was to identify unusual authentication behavior, determine whether multiple events were related, and assess the risk associated with the suspicious activity.

### Step 1 — Establish a Baseline for Login Activity

**SPL query:**

```spl
index=splunk_soc action=login
| stats count by status
| sort - count
```

This search grouped login events by status to establish a baseline of successful and failed authentication activity.

**Screenshot 7 — Login Activity Baseline by Authentication Status**

![Login Activity Baseline](https://github.com/Shan-light/Splunk-SOC-investigation/blob/5e3fe47e4063cf994dfa98b46774988d0e871770/image/Login%20Activity%20Baseline.png)

### Step 2 — Identify Users with Failed Login Attempts

**SPL query:**

```spl
index=splunk_soc action=login status=failed
| stats count by user
| sort - count
```

**Results:**

| User | Failed Login Attempts |
|---|---:|
| `jsmith` | 12 |
| `admin` | 1 |
| `mjones` | 1 |

The `jsmith` account had the highest number of failed login attempts, making it the primary account of interest.

**Screenshot 8 — Failed Login Attempts by User**

![Failed Logins by User](https://github.com/Shan-light/Splunk-SOC-investigation/blob/5e3fe47e4063cf994dfa98b46774988d0e871770/image/Failed%20Login%20Attempts%20by%20User.png)

### Step 3 — Identify Suspicious Source IP Addresses

**SPL query:**

```spl
index=splunk_soc action=login status=failed
| stats count by src_ip
| sort - count
```

**Finding:** The source IP `203.0.113.77` was associated with 12 failed login attempts, making it the primary source IP for further investigation.

**Screenshot 9 — Failed Login Attempts by Source IP**

![Failed Logins by Source IP](https://github.com/Shan-light/Splunk-SOC-investigation/blob/5e3fe47e4063cf994dfa98b46774988d0e871770/image/Failed%20Login%20Attempts%20by%20Source%20IP%20.png)

### Step 4 — Correlate the Suspicious User and Source IP

**SPL query:**

```spl
index=splunk_soc action=login status=failed
| stats count by user src_ip
| sort - count
```

**Finding:** The results linked the `jsmith` account to `203.0.113.77` for 12 failed login attempts. This indicates that the repeated failures were concentrated on one account and originated from one source.

**Screenshot 10 — Correlation of Failed Logins by User and Source IP**

![User and IP Correlation](https://github.com/Shan-light/Splunk-SOC-investigation/blob/5e3fe47e4063cf994dfa98b46774988d0e871770/image/Failed%20and%20Successful%20Logins%20from%20the%20Suspicious%20IP%20.png)

### Step 5 — Examine Individual Failed Authentication Events

**SPL query:**

```spl
index=splunk_soc action=login status=failed
| table timestamp user service action status src_ip dest_ip details
| sort timestamp
```

**Findings:**

- `mjones` had one failed SSH login, with `10.10.20.22` recorded as both source and destination.
- `admin` had one failed SSH login, with `10.10.20.31` recorded as both source and destination.
- `jsmith` had 12 failed SSH login attempts from `203.0.113.77` to `10.10.20.77`.
- All 12 failures associated with `jsmith` were attributed to `invalid_password`.
- The attempts occurred within seconds of one another.

The repeated, rapid authentication failures against the same account are consistent with automated password guessing or brute-force activity.

**Screenshot 11 — Detailed Review of Failed SSH Login Events**

![Detailed Failed SSH Login Events](https://github.com/Shan-light/Splunk-SOC-investigation/blob/5e3fe47e4063cf994dfa98b46774988d0e871770/image/Detailed%20Review%20of%20Failed%20SSH%20Login%20Events.png)

### Step 6 — Investigate Activity from the Suspicious Source IP

**SPL query:**

```spl
index=splunk_soc src_ip="203.0.113.77"
| table timestamp user service action status src_ip dest_ip details
| sort timestamp
```

**Findings:**

The search revealed 12 failed login attempts followed by a successful login from the suspicious source IP to `10.10.20.77`.

After the successful login, the event data recorded three commands:

1. `whoami` — identifies the account under which the command is running.
2. `ip addr` — displays network interface and IP address information.
3. `cat /etc/passwd` — reads the local Linux account information file.

In this context, the commands are consistent with possible post-login reconnaissance. However, these commands alone do not prove malicious intent.

**Screenshot 12 — Suspicious IP Investigation and Post-Authentication Activity**

![Suspicious IP Investigation](https://github.com/Shan-light/Splunk-SOC-investigation/blob/5e3fe47e4063cf994dfa98b46774988d0e871770/image/Investigate%20activity%20from%20the%20suspicious%20source%20IP.png)

### Step 7 — Confirm the Successful Authentication

**SPL query:**

```spl
index=splunk_soc src_ip="203.0.113.77" action=login
| stats count by user status
| sort - count
```

**Finding:** The results confirmed 12 failed login attempts and one successful login from the suspicious source IP. Together with the post-login commands identified in the previous step, this raises concern that the account may have been compromised.

**Screenshot 13 — Confirmation of Failed and Successful Logins**

![Authentication Outcome](https://github.com/Shan-light/Splunk-SOC-investigation/blob/5e3fe47e4063cf994dfa98b46774988d0e871770/image/Failed%20and%20Successful%20Logins%20from%20the%20Suspicious%20IP%20.png)

---

## 4. Investigation Findings and Conclusion

### Summary of Evidence

| Indicator | Finding |
|---|---|
| Primary account of interest | `jsmith` |
| Suspicious source IP | `203.0.113.77` |
| Destination host | `10.10.20.77` |
| Service | SSH |
| Failed login attempts | 12 |
| Successful login | 1 |
| Failure reason | `invalid_password` |
| Post-login commands | `whoami`, `ip addr`, `cat /etc/passwd` |

### Incident Assessment

**Classification: Potential Brute-Force Compromise**

The repeated failed SSH login attempts against `jsmith`, followed by successful authentication from the same source IP and commands consistent with reconnaissance, indicate a potentially compromised account.

The evidence supports a high level of concern about the activity, but it does not independently establish that the successful login was unauthorized. Additional investigation would be needed to confirm compromise and determine the extent of any impact.

### Recommended Response Actions

1. Validate whether the successful login was authorized.
2. Review additional authentication and endpoint logs for `10.10.20.77`.
3. Review the `jsmith` account's session activity and permissions.
4. If compromise is suspected, secure the account, revoke unauthorized sessions, and reset credentials.
5. Check for additional commands, persistence, privilege escalation, or access to sensitive files.

---

## 5. Skills Demonstrated

This project demonstrates hands-on practice with:

- Splunk Enterprise and Search Processing Language (SPL)
- Security log ingestion and data verification
- Authentication monitoring and failed-login analysis
- Event aggregation using `stats`
- Sorting results using `sort`
- Event-field selection using `table`
- User and source-IP correlation
- Investigation pivots and chronological event review
- SSH brute-force detection concepts
- Post-authentication activity analysis
- Incident assessment and response recommendations

---

## 6. Key SPL Queries

The following searches were used during the investigation.

### Count events

```spl
index=splunk_soc
| stats count
```

### Review login statuses

```spl
index=splunk_soc action=login
| stats count by status
| sort - count
```

### Failed logins by user

```spl
index=splunk_soc action=login status=failed
| stats count by user
| sort - count
```

### Failed logins by source IP

```spl
index=splunk_soc action=login status=failed
| stats count by src_ip
| sort - count
```

### Correlate user and source IP

```spl
index=splunk_soc action=login status=failed
| stats count by user src_ip
| sort - count
```

### Examine failed authentication events

```spl
index=splunk_soc action=login status=failed
| table timestamp user service action status src_ip dest_ip details
| sort timestamp
```

### Investigate the suspicious source IP

```spl
index=splunk_soc src_ip="203.0.113.77"
| table timestamp user service action status src_ip dest_ip details
| sort timestamp
```

### Confirm authentication outcomes

```spl
index=splunk_soc src_ip="203.0.113.77" action=login
| stats count by user status
| sort - count
```

---

## 7. Important Notes

- This project demonstrates a hands-on lab investigation and should not be presented as professional SOC employment experience.
- The classification is **potential compromise**, not confirmed compromise, because the available events do not independently establish whether the successful login was unauthorized.
- `203.0.113.77` is an IP address in a range reserved for documentation. Treat it as a lab indicator, not a verified real-world attacker IP.
- The screenshots referenced in this README must be placed in the `screenshots/` directory using the filenames shown above.

## Conclusion

This investigation used Splunk to analyze 40 security events, identify a concentrated pattern of failed SSH authentication attempts, correlate the activity with a user account and source IP, and uncover a subsequent successful login followed by commands consistent with reconnaissance.

The investigation demonstrates how SPL searches can support security monitoring, event correlation, suspicious activity analysis, and evidence-based incident assessment.
