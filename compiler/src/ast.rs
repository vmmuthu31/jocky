use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Program {
    pub sessions: Vec<ForensicSession>,
    pub statements: Vec<MethodCall>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MethodCall {
    pub module: String,
    pub function: String,
    pub args: Vec<String>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    Triage,
    IncidentResponse,
    NetworkTrace,
    DeepAudit,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicSession {
    pub target: String,
    pub warrant: String,
    pub profile: Option<Profile>,
    pub collect_items: Vec<CollectItem>,
    pub encrypt_algo: EncryptionAlgo,
    pub encrypt_key: String,
    pub transmit_endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectItem {
    pub artifact_type: ArtifactType,
    pub expression: Expression,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArtifactType {
    Registry,
    Memory,
    Network,
    Disk,
    Proc,
    Auditd,
    Ext4,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Expression {
    Identifier(String),
    StringLiteral(String),
    ProcessExpr { process: String },
    PipeExpr { left: Box<Expression>, right: Box<Expression> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EncryptionAlgo {
    Aes256,
    ChaCha20,
    MlKem,
}
