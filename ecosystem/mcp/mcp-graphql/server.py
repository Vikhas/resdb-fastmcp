"""MCP Server for ResilientDB - GraphQL integration."""
import asyncio
import json
import sys
import os
import time
from datetime import datetime
from typing import Any, Dict, List, Optional
import httpx

from fastmcp import FastMCP

from config import Config
from graphql_client import GraphQLClient
from rescontract_client import ResContractClient

# Initialize clients
graphql_client = GraphQLClient()
rescontract_client = ResContractClient()

# Create MCP server
mcp = FastMCP("resilientdb-mcp")

async def send_monitoring_data(tool_name: str, args: dict, result: Any, duration: float):
    """Send monitoring data to ResLens middleware."""
    try:
        async with httpx.AsyncClient() as client:
            await client.post(
                "http://localhost:3000/api/v1/mcp/prompts",
                json={
                    "tool": tool_name,
                    "args": args,
                    "result": str(result)[:1000] if result else "None",
                    "timestamp": datetime.now().isoformat(),
                    "duration": duration,
                    "resdb_metrics": {}
                },
                timeout=5.0
            )
    except Exception as e:
        print(f"Failed to send monitoring data to ResLens: {e}", file=sys.stderr)

# Helper functions
def _setup_resilientdb_path() -> str:
    """Setup path to ResilientDB resdb_driver for key generation."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    possible_paths = [
        os.path.join(script_dir, '../../graphql/resdb_driver'),
        '/Users/rahul/data/workspace/kanagrah/incubator-resilientdb/ecosystem/graphql/resdb_driver',
        os.path.join(script_dir, '../graphql/resdb_driver'),
        os.path.join(script_dir, '../../../ecosystem/graphql/resdb_driver'),
    ]
    
    for path in possible_paths:
        abs_path = os.path.abspath(path)
        if os.path.exists(abs_path):
            if abs_path not in sys.path:
                sys.path.insert(0, abs_path)
            return abs_path
    
    raise ImportError(
        f"Could not find ResilientDB resdb_driver directory. "
        f"Tried: {', '.join([os.path.abspath(p) for p in possible_paths])}"
    )

def _setup_sha3_shim():
    """Setup sha3 module shim using Python's built-in hashlib for Python 3.11+."""
    import hashlib
    import sys
    from types import ModuleType
    
    class SHA3_256:
        """SHA3-256 hash implementation using Python's built-in hashlib."""
        
        def __init__(self, data=None):
            """Initialize SHA3-256 hash object."""
            self._hash = hashlib.sha3_256()
            if data is not None:
                if isinstance(data, str):
                    data = data.encode('utf-8')
                self._hash.update(data)
        
        def update(self, data):
            """Update the hash with additional data."""
            if isinstance(data, str):
                data = data.encode('utf-8')
            self._hash.update(data)
        
        def hexdigest(self):
            """Return the hexadecimal digest of the hash."""
            return self._hash.hexdigest()
        
        def digest(self):
            """Return the binary digest of the hash."""
            return self._hash.digest()
    
    # Create a factory function that returns instances
    def sha3_256(data=None):
        """Factory function for SHA3-256 hash objects."""
        return SHA3_256(data)
    
    # Create a fake sha3 module and inject it into sys.modules
    sha3_module = ModuleType('sha3')
    sha3_module.sha3_256 = sha3_256
    
    # Only inject if sha3 is not already available
    if 'sha3' not in sys.modules:
        sys.modules['sha3'] = sha3_module

def generate_keypairs_internal() -> Dict[str, str]:
    """
    Generate Ed25519 keypairs for ResilientDB transactions.
    """
    try:
        _setup_resilientdb_path()
        # Setup sha3 shim before importing crypto (which imports sha3)
        _setup_sha3_shim()
        from crypto import generate_keypair
    except ImportError as e:
        raise ImportError(
            f"Could not import generate_keypair from ResilientDB crypto module: {e}"
        )
    
    signer = generate_keypair()
    recipient = generate_keypair()
    
    return {
        "signerPublicKey": signer.public_key,
        "signerPrivateKey": signer.private_key,
        "recipientPublicKey": recipient.public_key,
        "recipientPrivateKey": recipient.private_key
    }

async def analyze_transactions_internal(transaction_ids: list[str]) -> Dict[str, Any]:
    """
    Analyze a set of transactions and compute summary statistics.
    """
    transactions = []
    errors = []
    
    # Fetch all transactions
    for tx_id in transaction_ids:
        try:
            result = await graphql_client.get_transaction(tx_id)
            # Extract the actual transaction data from GraphQL response
            tx_data = result.get("getTransaction", {})
            if tx_data:
                transactions.append(tx_data)
        except Exception as e:
            errors.append({
                "transactionId": tx_id,
                "error": str(e)
            })
    
    if not transactions:
        return {
            "summary": {
                "total": 0,
                "successful": 0,
                "failed": len(errors),
                "message": "No transactions could be retrieved"
            },
            "transactions": [],
            "errors": errors
        }
    
    # Compute statistics
    total = len(transactions)
    amounts = []
    operations = {}
    types = set()
    signers = set()
    public_keys = set()
    
    for tx in transactions:
        # Collect amounts
        if "amount" in tx and tx["amount"] is not None:
            try:
                amounts.append(int(tx["amount"]))
            except (ValueError, TypeError):
                pass
        
        # Count operations
        op = tx.get("operation", "UNKNOWN")
        operations[op] = operations.get(op, 0) + 1
        
        # Collect types
        if "type" in tx and tx["type"]:
            types.add(str(tx["type"]))
        
        # Collect signers
        if "signerPublicKey" in tx and tx["signerPublicKey"]:
            signers.add(str(tx["signerPublicKey"]))
        
        # Collect public keys
        if "publicKey" in tx and tx["publicKey"]:
            public_keys.add(str(tx["publicKey"]))
    
    # Build summary
    summary = {
        "total": total,
        "successful": len(transactions),
        "failed": len(errors),
        "byOperation": operations,
        "distinctTypes": list(types),
        "distinctSigners": len(signers),
        "distinctPublicKeys": len(public_keys)
    }
    
    # Add amount statistics if available
    if amounts:
        summary["amountStats"] = {
            "min": min(amounts),
            "max": max(amounts),
            "average": sum(amounts) / len(amounts),
            "total": sum(amounts),
            "count": len(amounts)
        }
    
    return {
        "summary": summary,
        "transactions": transactions,
        "errors": errors
    }

# Tools

@mcp.tool()
async def generateKeys() -> str:
    """Generate Ed25519 cryptographic keypairs (signer and recipient) for ResilientDB transactions. Returns signerPublicKey, signerPrivateKey, recipientPublicKey, and recipientPrivateKey. Use this tool to generate keys before creating transactions, or it will be automatically called when needed for postTransaction."""
    start_time = time.time()
    result = None
    try:
        keys = generate_keypairs_internal()
        result_dict = {
            "signerPublicKey": keys["signerPublicKey"],
            "signerPrivateKey": keys["signerPrivateKey"],
            "recipientPublicKey": keys["recipientPublicKey"],
            "recipientPrivateKey": keys["recipientPrivateKey"],
            "message": "Keys generated successfully. Use these keys with postTransaction tool."
        }
        result = json.dumps(result_dict, indent=2)
        return result
    finally:
        duration = time.time() - start_time
        asyncio.create_task(send_monitoring_data("generateKeys", {}, result, duration))

@mcp.tool()
async def getTransaction(transactionId: str) -> str:
    """Get asset transaction details by transaction ID using GraphQL (port 8000). Returns RetrieveTransaction with id, version, amount, uri, type, publicKey, operation, metadata, asset, and signerPublicKey."""
    start_time = time.time()
    result = None
    try:
        data = await graphql_client.get_transaction(transactionId)
        result = json.dumps(data, indent=2)
        return result
    finally:
        duration = time.time() - start_time
        asyncio.create_task(send_monitoring_data("getTransaction", {"transactionId": transactionId}, result, duration))

@mcp.tool()
async def postTransaction(operation: str, amount: int, asset: Any, signerPublicKey: str = None, signerPrivateKey: str = None, recipientPublicKey: str = None) -> str:
    """Post a new asset transaction to ResilientDB using GraphQL (port 8000). Requires PrepareAsset with: operation (String), amount (Int), signerPublicKey (String), signerPrivateKey (String), recipientPublicKey (String), and asset (JSON). Returns CommitTransaction with transaction ID. If keys are not provided, automatically generate them using generateKeys tool first."""
    start_time = time.time()
    result = None
    args = {
        "operation": operation,
        "amount": amount,
        "asset": asset,
        "signerPublicKey": signerPublicKey,
        "signerPrivateKey": signerPrivateKey,
        "recipientPublicKey": recipientPublicKey
    }
    try:
        # Auto-generate keys if not provided or if any key is missing/empty
        if not all([signerPublicKey, signerPrivateKey, recipientPublicKey]):
            keys = generate_keypairs_internal()
            signerPublicKey = keys["signerPublicKey"]
            signerPrivateKey = keys["signerPrivateKey"]
            recipientPublicKey = keys["recipientPublicKey"]
        
        # Process asset - ensure it has 'data' field
        if isinstance(asset, str):
            try:
                asset = json.loads(asset)
            except json.JSONDecodeError:
                pass  # Keep as string if not valid JSON
        
        # If asset is a dict but doesn't have 'data' field, wrap it
        if isinstance(asset, dict) and "data" not in asset:
            asset = {"data": asset}
        elif not isinstance(asset, dict):
            # If it's still a string or other type, wrap it in data
            asset = {"data": asset}
        
        # Build PrepareAsset from individual arguments
        data = {
            "operation": operation,
            "amount": amount,
            "signerPublicKey": signerPublicKey,
            "signerPrivateKey": signerPrivateKey,
            "recipientPublicKey": recipientPublicKey,
            "asset": asset
        }
        res = await graphql_client.post_transaction(data)
        result = json.dumps(res, indent=2)
        return result
    finally:
        duration = time.time() - start_time
        asyncio.create_task(send_monitoring_data("postTransaction", args, result, duration))

@mcp.tool()
async def analyzeTransactions(transactionIds: List[str]) -> str:
    """Analyze a set of transactions by their IDs and compute summary statistics. Returns summary with counts by operation type, amount statistics (min/max/average), distinct types, signers, and public keys. Also returns raw transaction data and any errors encountered. Useful for understanding transaction patterns and identifying outliers."""
    start_time = time.time()
    result = None
    try:
        if not transactionIds:
            raise ValueError("transactionIds list cannot be empty")
        
        # Limit to 20 transactions to avoid performance issues
        if len(transactionIds) > 20:
            transactionIds = transactionIds[:20]
        
        res = await analyze_transactions_internal(transactionIds)
        result = json.dumps(res, indent=2)
        return result
    finally:
        duration = time.time() - start_time
        asyncio.create_task(send_monitoring_data("analyzeTransactions", {"transactionIds": transactionIds}, result, duration))

@mcp.tool()
async def get(key: str) -> str:
    """Retrieves a value from ResilientDB by key using HTTP REST API (Crow server on port 18000)."""
    start_time = time.time()
    result = None
    try:
        res = await graphql_client.get_key_value(key)
        result = json.dumps(res, indent=2)
        return result
    finally:
        duration = time.time() - start_time
        asyncio.create_task(send_monitoring_data("get", {"key": key}, result, duration))

@mcp.tool()
async def set(key: str, value: Any) -> str:
    """Stores a key-value pair in ResilientDB using HTTP REST API (Crow server on port 18000)."""
    start_time = time.time()
    result = None
    try:
        res = await graphql_client.set_key_value(key, value)
        result = json.dumps(res, indent=2)
        return result
    finally:
        duration = time.time() - start_time
        asyncio.create_task(send_monitoring_data("set", {"key": key, "value": value}, result, duration))

@mcp.tool()
async def introspectGraphQL() -> str:
    """Introspect the ResilientDB GraphQL schema to see available types and operations."""
    start_time = time.time()
    result = None
    try:
        query = "{ __schema { types { name } } }"
        res = await graphql_client.execute_query(query)
        result = json.dumps(res, indent=2)
        return result
    finally:
        duration = time.time() - start_time
        asyncio.create_task(send_monitoring_data("introspectGraphQL", {}, result, duration))

@mcp.tool()
async def compileContract(sol_path: str, output_name: str) -> str:
    """Compile a Solidity smart contract to JSON format."""
    start_time = time.time()
    result = None
    try:
        res = rescontract_client.compile_solidity(sol_path, output_name)
        result = json.dumps({"status": "success", "output": res}, indent=2)
        return result
    finally:
        duration = time.time() - start_time
        asyncio.create_task(send_monitoring_data("compileContract", {"sol_path": sol_path, "output_name": output_name}, result, duration))

@mcp.tool()
async def deployContract(config_path: str, contract_path: str, name: str, owner_address: str, arguments: str = "") -> str:
    """Deploy a smart contract to ResilientDB."""
    start_time = time.time()
    result = None
    args = {
        "config_path": config_path,
        "contract_path": contract_path,
        "name": name,
        "owner_address": owner_address,
        "arguments": arguments
    }
    try:
        res = rescontract_client.deploy_contract(config_path, contract_path, name, arguments, owner_address)
        result = json.dumps({"status": "success", "output": res}, indent=2)
        return result
    finally:
        duration = time.time() - start_time
        asyncio.create_task(send_monitoring_data("deployContract", args, result, duration))

@mcp.tool()
async def executeContract(config_path: str, sender_address: str, contract_address: str, function_name: str, arguments: str = "") -> str:
    """Execute a function on a deployed smart contract."""
    start_time = time.time()
    result = None
    args = {
        "config_path": config_path,
        "sender_address": sender_address,
        "contract_address": contract_address,
        "function_name": function_name,
        "arguments": arguments
    }
    try:
        res = rescontract_client.execute_contract(config_path, sender_address, contract_address, function_name, arguments)
        result = json.dumps({"status": "success", "output": res}, indent=2)
        return result
    finally:
        duration = time.time() - start_time
        asyncio.create_task(send_monitoring_data("executeContract", args, result, duration))

@mcp.tool()
async def createAccount(config_path: str) -> str:
    """Create a new ResilientDB account for smart contract operations."""
    start_time = time.time()
    result = None
    try:
        res = rescontract_client.create_account(config_path)
        result = json.dumps({"status": "success", "output": res}, indent=2)
        return result
    finally:
        duration = time.time() - start_time
        asyncio.create_task(send_monitoring_data("createAccount", {"config_path": config_path}, result, duration))

@mcp.tool()
async def checkReplicasStatus() -> str:
    """Check the status of ResilientDB contract service replicas. Returns information about how many of the 5 required replicas are currently running."""
    start_time = time.time()
    result = None
    try:
        status = rescontract_client.check_replica_status()
        response = f"{status['message']}\n\n"
        if status['count'] > 0:
            response += "Running processes:\n"
            for i, detail in enumerate(status['details'], 1):
                detail_short = detail[:150] + "..." if len(detail) > 150 else detail
                response += f"{i}. {detail_short}\n"
        if not status['running']:
            response += "\n⚠️ System is NOT ready for operations. Use startReplicas tool to start the cluster."
        else:
            response += "\n✅ System is ready for contract operations."
        result = json.dumps({"status": status, "message": response}, indent=2)
        return result
    finally:
        duration = time.time() - start_time
        asyncio.create_task(send_monitoring_data("checkReplicasStatus", {}, result, duration))

@mcp.tool()
async def startReplicas() -> str:
    """Start or restart the ResilientDB contract service replica cluster. WARNING: This will wipe the existing blockchain state."""
    start_time = time.time()
    result = None
    try:
        res = rescontract_client.start_replica_cluster()
        result = json.dumps({"status": "success", "output": res, "warning": "The blockchain state has been reset. You will need to create new accounts and redeploy contracts."}, indent=2)
        return result
    finally:
        duration = time.time() - start_time
        asyncio.create_task(send_monitoring_data("startReplicas", {}, result, duration))

@mcp.tool()
async def getServerLogs(server_id: int = 0, lines: int = 50) -> str:
    """Get recent log entries from a specific replica server."""
    start_time = time.time()
    result = None
    try:
        if server_id < 0 or server_id > 3:
            raise ValueError(f"server_id must be between 0 and 3. Got: {server_id}")
        log_file = f"server{server_id}.log"
        res = rescontract_client.get_logs(log_file, lines)
        result = json.dumps({"log_file": log_file, "lines": lines, "content": res}, indent=2)
        return result
    finally:
        duration = time.time() - start_time
        asyncio.create_task(send_monitoring_data("getServerLogs", {"server_id": server_id, "lines": lines}, result, duration))

@mcp.tool()
async def getClientLogs(lines: int = 50) -> str:
    """Get recent log entries from the client proxy."""
    start_time = time.time()
    result = None
    try:
        res = rescontract_client.get_logs("client.log", lines)
        result = json.dumps({"log_file": "client.log", "lines": lines, "content": res}, indent=2)
        return result
    finally:
        duration = time.time() - start_time
        asyncio.create_task(send_monitoring_data("getClientLogs", {"lines": lines}, result, duration))

@mcp.tool()
async def validateConfig(config_path: str) -> str:
    """Validate a ResilientDB configuration file. Checks for file existence, correct format, valid addresses, valid ports, and other configuration errors."""
    start_time = time.time()
    result = None
    try:
        res = rescontract_client.validate_config(config_path)
        result = json.dumps(res, indent=2)
        return result
    finally:
        duration = time.time() - start_time
        asyncio.create_task(send_monitoring_data("validateConfig", {"config_path": config_path}, result, duration))

@mcp.tool()
async def healthCheck() -> str:
    """Perform a comprehensive health check of all ResilientDB system components. Checks replicas, REST API, GraphQL API, and network latency."""
    start_time = time.time()
    result = None
    try:
        health = rescontract_client.health_check()
        status_emoji = {
            "healthy": "✅",
            "degraded": "⚠️",
            "down": "❌"
        }
        overall_emoji = status_emoji.get(health["overall_status"], "❓")
        report = f"🏥 ResilientDB Health Check Report\n\n"
        report += f"Overall Status: {overall_emoji} {health['overall_status'].upper()}\n\n"
        report += "📊 Components:\n"
        rep = health["replicas"]
        rep_emoji = status_emoji.get(rep["status"], "❓")
        report += f"  {rep_emoji} Replicas: {rep['message']}\n"
        rest = health["rest_api"]
        rest_emoji = status_emoji.get(rest["status"], "❓")
        if rest["status"] == "healthy":
            report += f"  {rest_emoji} REST API: Responding ({rest['url']}) - {rest['latency_ms']}ms\n"
        else:
            report += f"  {rest_emoji} REST API: Down ({rest['url']}) - {rest.get('error', 'Unknown error')}\n"
        gql = health["graphql_api"]
        gql_emoji = status_emoji.get(gql["status"], "❓")
        if gql["status"] == "healthy":
            report += f"  {gql_emoji} GraphQL API: Responding ({gql['url']}) - {gql['latency_ms']}ms\n"
        else:
            report += f"  {gql_emoji} GraphQL API: Down ({gql['url']}) - {gql.get('error', 'Unknown error')}\n"
        if health["overall_status"] != "healthy":
            report += "\n💡 Recommendations:\n"
            if health["replicas"]["status"] != "healthy":
                report += "  • Start replicas using the startReplicas tool\n"
            if health["rest_api"]["status"] != "healthy":
                report += "  • Check if ResilientDB REST service is running on port 18000\n"
            if health["graphql_api"]["status"] != "healthy":
                report += "  • Check if ResilientDB GraphQL service is running on port 8000\n"
        result = json.dumps({"health": health, "report": report}, indent=2)
        return result
    finally:
        duration = time.time() - start_time
        asyncio.create_task(send_monitoring_data("healthCheck", {}, result, duration))

@mcp.tool()
async def listAllAccounts() -> str:
    """List all accounts found on the ResilientDB blockchain. Parses server logs to find all created accounts and their activity levels."""
    start_time = time.time()
    result = None
    try:
        accounts = rescontract_client.list_all_accounts()
        if not accounts:
            response = "No accounts found in the system logs.\n\nCreate an account using the createAccount tool."
        else:
            response = f"👥 ResilientDB Accounts ({len(accounts)} total)\n\n"
            for i, acc in enumerate(accounts, 1):
                response += f"{i}. {acc['address']}\n"
                response += f"   Created: {acc['created']}\n"
                response += f"   Activity: {acc['activity_count']} log entries\n\n"
        result = json.dumps({"accounts": accounts, "message": response}, indent=2)
        return result
    finally:
        duration = time.time() - start_time
        asyncio.create_task(send_monitoring_data("listAllAccounts", {}, result, duration))

@mcp.tool()
async def getTransactionHistory(limit: int = 50, tx_type: str = None, address: str = None) -> str:
    """Query transaction history from the ResilientDB blockchain. Parses server logs to extract DEPLOY and EXECUTE transactions with filtering options."""
    start_time = time.time()
    result = None
    try:
        transactions = rescontract_client.get_transaction_history(limit, tx_type, address)
        if not transactions:
            response = "📜 No transactions found matching the criteria.\n\nTransactions will appear here after deploying contracts or executing functions."
        else:
            response = f"📜 Transaction History ({len(transactions)} transactions"
            if tx_type:
                response += f", type={tx_type}"
            if address:
                response += f", address={address[:10]}..."
            response += ")\n\n"
            for i, tx in enumerate(transactions, 1):
                if tx["type"] == "DEPLOY":
                    response += f"{i}. [DEPLOY] {tx['timestamp']}\n"
                    response += f"   Caller: {tx['caller']}\n"
                    response += f"   Contract: {tx['contract_name']}\n\n"
                elif tx["type"] == "EXECUTE":
                    response += f"{i}. [EXECUTE] {tx['timestamp']}\n"
                    response += f"   Caller: {tx['caller']}\n"
                    response += f"   Contract: {tx['contract_address']}\n"
                    response += f"   Function: {tx['function']}\n\n"
        result = json.dumps({"transactions": transactions, "message": response}, indent=2)
        return result
    finally:
        duration = time.time() - start_time
        asyncio.create_task(send_monitoring_data("getTransactionHistory", {"limit": limit, "tx_type": tx_type, "address": address}, result, duration))

@mcp.tool()
async def searchLogs(query: str, server_id: int = None, lines: int = 100) -> str:
    """Search for a text pattern in the server logs."""
    start_time = time.time()
    result = None
    try:
        res = rescontract_client.search_logs(query, server_id, lines)
        result = json.dumps({"query": query, "results": res}, indent=2)
        return result
    finally:
        duration = time.time() - start_time
        asyncio.create_task(send_monitoring_data("searchLogs", {"query": query, "server_id": server_id, "lines": lines}, result, duration))

@mcp.tool()
async def getConsensusMetrics() -> str:
    """Get internal consensus metrics from the system logs. Extracts the current View Number, Sequence Number, and Primary Replica ID."""
    start_time = time.time()
    result = None
    try:
        metrics = rescontract_client.get_consensus_metrics()
        report = f"📊 Consensus Metrics\n\n"
        report += f"👑 Primary Replica: {metrics['primary_id']}\n"
        report += f"👀 Current View: {metrics['view']}\n"
        report += f"🔢 Sequence Number: {metrics['sequence']}\n"
        report += f"🟢 Active Replicas: {metrics['active_replicas']}/5\n"
        result = json.dumps({"metrics": metrics, "report": report}, indent=2)
        return result
    finally:
        duration = time.time() - start_time
        asyncio.create_task(send_monitoring_data("getConsensusMetrics", {}, result, duration))

@mcp.tool()
async def archiveLogs() -> str:
    """Archive all current log files to a ZIP file. Creates a timestamped ZIP file containing server0-3.log, client.log, and configuration files."""
    start_time = time.time()
    result = None
    try:
        archive_path = rescontract_client.archive_logs()
        result = json.dumps({"status": "success", "archive_path": archive_path, "message": f"📦 Logs archived successfully!\n\nLocation: {archive_path}"}, indent=2)
        return result
    finally:
        duration = time.time() - start_time
        asyncio.create_task(send_monitoring_data("archiveLogs", {}, result, duration))

if __name__ == "__main__":
    mcp.run()