from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
import mysql.connector

app = FastAPI(title="Payroll Management with RBAC")

# --------------------------
# Database Connection
# --------------------------
def get_db_connection():
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="Swetha@157",  # replace with your MySQL password
        database="rbac"
    )
    return conn

# --------------------------
# Models
# --------------------------
class UserLogin(BaseModel):
    username: str
    password: str  # optional: can validate later

class UpdateSalaryRequest(BaseModel):
    employee_id: int
    new_salary: float

class AddEmployeeRequest(BaseModel):
    employee_name: str
    salary: float

class DeleteEmployeeRequest(BaseModel):
    employee_id: int

# --------------------------
# Helper Functions
# --------------------------
def get_user_role(username: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT role FROM users WHERE username=%s", (username,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

def get_permissions(role: str):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT permission FROM roles_permissions WHERE role=%s", (role,))
    permissions = [p[0] for p in cursor.fetchall()]
    conn.close()
    return permissions

# --------------------------
# Endpoints
# --------------------------
@app.post("/login")
def login(user: UserLogin):
    role = get_user_role(user.username)
    if not role:
        raise HTTPException(status_code=401, detail="Invalid username")
    # Note: password check can be implemented here
    return {"username": user.username, "role": role}

@app.get("/view_salary")
def view_salary(username: str):
    role = get_user_role(username)
    if not role:
        raise HTTPException(status_code=401, detail="User not found")
    permissions = get_permissions(role)
    if "SELECT" not in permissions:
        raise HTTPException(status_code=403, detail="Permission denied")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM employee_salary")
    result = cursor.fetchall()
    conn.close()
    return [{"id": r[0], "name": r[1], "salary": float(r[2])} for r in result]

@app.put("/update_salary")
def update_salary(username: str, request: UpdateSalaryRequest):
    role = get_user_role(username)
    if not role:
        raise HTTPException(status_code=401, detail="User not found")
    permissions = get_permissions(role)
    if "UPDATE" not in permissions:
        raise HTTPException(status_code=403, detail="Permission denied")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE employee_salary SET salary=%s WHERE id=%s", (request.new_salary, request.employee_id))
    conn.commit()
    conn.close()
    return {"message": f"Salary updated for employee ID {request.employee_id}"}

@app.post("/add_employee")
def add_employee(username: str, request: AddEmployeeRequest):
    role = get_user_role(username)
    if not role:
        raise HTTPException(status_code=401, detail="User not found")
    permissions = get_permissions(role)
    if "INSERT" not in permissions:
        raise HTTPException(status_code=403, detail="Permission denied")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO employee_salary (employee_name, salary) VALUES (%s, %s)", 
                   (request.employee_name, request.salary))
    conn.commit()
    conn.close()
    return {"message": f"New employee {request.employee_name} added"}

@app.delete("/delete_employee")
def delete_employee(username: str, request: DeleteEmployeeRequest):
    role = get_user_role(username)
    if not role:
        raise HTTPException(status_code=401, detail="User not found")
    permissions = get_permissions(role)
    if "DELETE" not in permissions:
        raise HTTPException(status_code=403, detail="Permission denied")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM employee_salary WHERE id=%s", (request.employee_id,))
    conn.commit()
    conn.close()
    return {"message": f"Employee ID {request.employee_id} deleted"}
