
import ast
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Any, Optional, Set
import pandas as pd

# -----------------------------
# Parse Tree Extraction Utility
# -----------------------------
def get_parse_tree(source_code: str) -> ast.AST:
    """
    Return the Python AST for the given source code.
    """
    return ast.parse(source_code)

# -----------------------------
# Assignment Parsing Utilities
# -----------------------------
@dataclass
class Assignment:
    target: str
    value: Any  # ast node or python constant (after eval where possible)
    node: ast.AST

def extract_assignments(tree: ast.AST) -> List[Assignment]:
    """
    Extract simple assignments (Name = <expr>) at module and function scope.
    """
    assigns: List[Assignment] = []

    class Visitor(ast.NodeVisitor):
        def visit_Assign(self, node: ast.Assign):
            if len(node.targets) == 1:
                tgt = node.targets[0]
                # Simple Name = expr
                if isinstance(tgt, ast.Name):
                    assigns.append(Assignment(target=tgt.id, value=node.value, node=node))
                # Tuple unpacking: (a, b, c) = (x, y, z)
                elif isinstance(tgt, (ast.Tuple, ast.List)) and isinstance(node.value, (ast.Tuple, ast.List)):
                    for sub_t, sub_v in zip(tgt.elts, node.value.elts):
                        if isinstance(sub_t, ast.Name):
                            assigns.append(Assignment(target=sub_t.id, value=sub_v, node=node))

            self.generic_visit(node)
    Visitor().visit(tree)
    return assigns

# -----------------------------
# Function Signature & Calls
# -----------------------------
@dataclass
class FunctionInfo:
    name: str
    params: List[str]
    body: List[ast.stmt]

def extract_functions(tree: ast.AST) -> Dict[str, FunctionInfo]:
    funcs: Dict[str, FunctionInfo] = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            params = [a.arg for a in node.args.args]
            funcs[node.name] = FunctionInfo(name=node.name, params=params, body=node.body)
    return funcs

def extract_calls(tree: ast.AST) -> List[ast.Call]:
    calls: List[ast.Call] = []
    class C(ast.NodeVisitor):
        def visit_Call(self, node: ast.Call):
            calls.append(node)
            self.generic_visit(node)
    C().visit(tree)
    return calls

# -----------------------------
# Simple Constant Evaluator
# -----------------------------
def eval_simple_expr(expr: ast.AST, env: Dict[str, Any]) -> Optional[Any]:
    """
    Evaluate a narrow subset of Python expressions safely with a provided env:
    - ast.Constant
    - ast.Name (lookup in env)
    - ast.BinOp with + or - on evaluable sub-exprs
    - No function calls; no attribute access.
    Returns None if not evaluable.
    """
    if isinstance(expr, ast.Constant):
        return expr.value
    if isinstance(expr, ast.Name):
        return env.get(expr.id)
    if isinstance(expr, ast.BinOp):
        left = eval_simple_expr(expr.left, env)
        right = eval_simple_expr(expr.right, env)
        if left is None or right is None:
            return None
        if isinstance(expr.op, ast.Add):
            return left + right
        if isinstance(expr.op, ast.Sub):
            return left - right
    if isinstance(expr, ast.UnaryOp) and isinstance(expr.op, ast.USub):
        val = eval_simple_expr(expr.operand, env)
        if val is not None:
            return -val
    # Not supported
    return None

# -----------------------------
# Data-Flow Graph Construction
# -----------------------------
@dataclass
class Edge:
    src: str
    dst: str
    kind: str  # "assign", "param", "binop", "result"

@dataclass
class DataFlow:
    edges: List[Edge] = field(default_factory=list)
    values: Dict[str, Any] = field(default_factory=dict)  # constant-propagated values

    def add_edge(self, src: str, dst: str, kind: str):
        self.edges.append(Edge(src, dst, kind))

    def to_dataframe(self) -> pd.DataFrame:
        return pd.DataFrame([e.__dict__ for e in self.edges])



def __label(node: ast.AST) -> str:
    if isinstance(node, ast.Constant):
        return str(node.value)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub) and isinstance(node.operand, ast.Constant):
        return f"-{node.operand.value}"
    if isinstance(node, ast.Name):
        return node.id
    return ast.dump(node, include_attributes=False)



def _label(node: ast.AST) -> str:
    if isinstance(node, ast.Constant):
        return str(node.value)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub) and isinstance(node.operand, ast.Constant):
        return f"-{node.operand.value}"
    if isinstance(node, ast.Name):
        return node.id
    return ast.dump(node, include_attributes=False)

def build_data_flow(source_code: str) -> Tuple[DataFlow, Dict[str, FunctionInfo]]:
    tree = get_parse_tree(source_code)
    df = DataFlow()
    funcs = extract_functions(tree)
    assigns = extract_assignments(tree)

    # First pass: evaluate module-level constants and add assign edges
    env: Dict[str, Any] = {}
    for a in assigns:
        # Attempt to evaluate RHS
        val = eval_simple_expr(a.value, env)
        # Record value if constant
        if val is not None:
            env[a.target] = val
            df.values[a.target] = val
        # Build edges from value or names used in RHS to target
        # If RHS is a Constant -> "-100" -> val2
        if isinstance(a.value, ast.Constant):
            df.add_edge(str(a.value.value), a.target, "assign")
        elif isinstance(a.value, ast.UnaryOp):
            df.add_edge(_label(a.value), a.target, "assign")
        elif isinstance(a.value, ast.Name):
            df.add_edge(a.value.id, a.target, "assign")
        elif isinstance(a.value, ast.BinOp):
            # Connect both sides to the target
            left = a.value.left
            right = a.value.right
            df.add_edge(_label(left), a.target, "binop")
            df.add_edge(_label(right), a.target, "binop")
            df.add_edge(_label(right), a.target, "binop")

    # Handle function call argument mapping
    calls = extract_calls(tree)
    for c in calls:
        if isinstance(c.func, ast.Name) and c.func.id in funcs:
            finfo = funcs[c.func.id]
            # map positional args only + propagate constant values into params
            call_env = {}
            for arg_node, param in zip(c.args, finfo.params):
                # Make an edge from the argument expression to the parameter name
                label = _label(arg_node)
                val = None
                if isinstance(arg_node, ast.Name):
                    val = env.get(arg_node.id)
                elif isinstance(arg_node, ast.Constant):
                    val = arg_node.value
                df.add_edge(label, param, "param")
                if val is not None:
                    call_env[param] = val
                    df.values[param] = val

            # Within the function, evaluate res from params based on simpleCalculator's logic
            # Detect the if op == '+' / '-' pattern and compute res if possible
            for stmt in finfo.body:
                if isinstance(stmt, ast.Assign) and len(stmt.targets)==1 and isinstance(stmt.targets[0], ast.Name):
                    # e.g., res = 0
                    tgt = stmt.targets[0].id
                    val = eval_simple_expr(stmt.value, call_env)
                    if val is not None:
                        call_env[tgt] = val
                        df.values[tgt] = val
                elif isinstance(stmt, ast.If):
                    # evaluate the condition if possible
                    cond_val = None
                    try:
                        # Only handle op == '+' or op == '-'
                        if isinstance(stmt.test, ast.Compare) and isinstance(stmt.test.left, ast.Name) and stmt.test.left.id in call_env:
                            left_val = call_env[stmt.test.left.id]
                            if len(stmt.test.ops)==1 and isinstance(stmt.test.ops[0], ast.Eq):
                                right = stmt.test.comparators[0]
                                if isinstance(right, ast.Constant):
                                    cond_val = (left_val == right.value)
                    except Exception:
                        cond_val = None

                    # choose the taken branch if known; otherwise analyze both for edges
                    branches = []
                    if cond_val is True:
                        branches = [stmt.body]
                    elif cond_val is False:
                        branches = [stmt.orelse]
                    else:
                        branches = [stmt.body, stmt.orelse]

                    for branch in branches:
                        for s in branch:
                            if isinstance(s, ast.Assign) and isinstance(s.targets[0], ast.Name):
                                tgt = s.targets[0].id
                                # Connect operands to target
                                if isinstance(s.value, ast.BinOp):
                                    left, right = s.value.left, s.value.right
                                    df.add_edge(__label(left), tgt, "binop")
                                    df.add_edge(__label(right), tgt, "binop")
                                # Try to evaluate
                                val = eval_simple_expr(s.value, call_env)
                                if val is not None:
                                    call_env[tgt] = val
                                    df.values[tgt] = val

    return df, funcs

# -----------------------------
# Flow Generation
# -----------------------------
def generate_flow_path(df: DataFlow, start_token: str, end_value: Any) -> Optional[List[str]]:
    """
    Given a start token (e.g., '-100') and an end_value (e.g., 900), try to find
    a path like -100 -> val2 -> v2 -> res -> 900.
    We find a path to a variable that evaluates to `end_value`, then append the sink token.
    """
    # Build adjacency from edges
    adj: Dict[str, Set[str]] = {}
    for e in df.edges:
        adj.setdefault(e.src, set()).add(e.dst)

    # Identify variable(s) whose propagated value equals end_value
    end_vars = {name for name, val in df.values.items() if val == end_value}

    # BFS from start_token to any end_var
    from collections import deque
    q = deque([(start_token, [start_token])])
    seen = {start_token}
    while q:
        cur, path = q.popleft()
        if cur in end_vars:
            # Found a variable with the end value; append the end literal
            return path + [str(end_value)]
        for nxt in adj.get(cur, []):
            if nxt not in seen:
                seen.add(nxt)
                q.append((nxt, path + [nxt]))
    return None

# -----------------------------
# Main: run analysis on calc.py
# -----------------------------
def main(path: str = "calc.py"):
    src = open(path, "r", encoding="utf-8").read()
    df, funcs = build_data_flow(src)

    # Compute constant env for top-level values using our df.values
    # Try to evaluate the program's final result by simulating simpleCalculator with constants.
    # We know from calc.py that the call is: data = simpleCalculator(val1, val2, op)
    # We'll evaluate it quickly here for reporting.
    import ast
    tree = ast.parse(src)
    final_value = None
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets)==1 and isinstance(node.value, ast.Call):
            call = node.value
            if isinstance(call.func, ast.Name) and call.func.id == "simpleCalculator":
                # pull args from df.values if possible
                def eval_arg(n):
                    if isinstance(n, ast.Constant): return n.value
                    if isinstance(n, ast.Name): return df.values.get(n.id)
                    return None
                args = [eval_arg(a) for a in call.args]
                if all(a is not None for a in args):
                    v1, v2, operation = args
                    if operation == "+":
                        final_value = v1 + v2
                    elif operation == "-":
                        final_value = v1 - v2

    # Build a pandas DataFrame of edges
    edges_df = df.to_dataframe()

    # Try to find the flow path requested
    start_token = "-100"
    end_value = final_value if final_value is not None else 900
    path = generate_flow_path(df, start_token, end_value)

    print("=== Parse Tree (abbrev) ===")
    print(ast.dump(get_parse_tree(src), indent=2, include_attributes=False)[:600], "...")
    print("\n=== Functions Discovered ===")
    for f in funcs.values():
        print(f"- {f.name}({', '.join(f.params)}) with {len(f.body)} stmt(s)")

    print("\n=== Constant-Propagated Values ===")
    print(df.values)

    print("\n=== Data-Flow Edges ===")
    print(edges_df)

    print("\n=== Output Flow ===")
    if path:
        print(" -> ".join(path))
    else:
        print("No path found from", start_token, "to", end_value)

if __name__ == "__main__":
    main(f"calc.py")
