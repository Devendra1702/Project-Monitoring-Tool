# streamlit_app.py
import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, date
from sqlalchemy import create_engine, Column, Integer, String, Date, Text, Table, MetaData
from sqlalchemy.orm import sessionmaker
from werkzeug.security import generate_password_hash, check_password_hash
import io, csv, os

DB_PATH = "sqlite:///app.db"
engine = create_engine(DB_PATH, connect_args={"check_same_thread": False})
metadata = MetaData()

# Simple tables (SQLAlchemy Core)
users_tbl = Table(
    'users', metadata,
    Column('id', Integer, primary_key=True),
    Column('username', String, unique=True),
    Column('display_name', String),
    Column('role', String),  # 'admin' or 'user'
    Column('password_hash', String),
)

projects_tbl = Table(
    'projects', metadata,
    Column('id', Integer, primary_key=True),
    Column('code', String, unique=True),
    Column('name', String),
    Column('baseline_start', Date),
    Column('baseline_end', Date),
)

tasks_tbl = Table(
    'tasks', metadata,
    Column('id', Integer, primary_key=True),
    Column('project_code', String),
    Column('title', String),
    Column('planned_start', Date),
    Column('planned_end', Date),
    Column('actual_end', Date),
    Column('percent_complete', Integer),
    Column('status', String),
    Column('owner', String),
)

issues_tbl = Table(
    'issues', metadata,
    Column('id', Integer, primary_key=True),
    Column('project_code', String),
    Column('task_id', Integer),
    Column('title', String),
    Column('cause', String),
    Column('owner', String),
    Column('severity', String),
    Column('status', String),
)

metadata.create_all(engine)
Session = sessionmaker(bind=engine)
db = Session()

# Helper functions
def seed_admin():
    q = db.execute(users_tbl.select()).fetchall()
    if len(q) == 0:
        pw = "Micro@123"  # change on first login
        db.execute(users_tbl.insert().values(
            username="admin",
            display_name="Administrator",
            role="admin",
            password_hash=generate_password_hash(pw)
        ))
        db.commit()

def get_user(username):
    r = db.execute(users_tbl.select().where(users_tbl.c.username==username)).first()
    return r

def create_user(username, display_name, password, role="user"):
    if get_user(username): return False
    db.execute(users_tbl.insert().values(
        username=username,
        display_name=display_name,
        role=role,
        password_hash=generate_password_hash(password)
    ))
    db.commit()
    return True

# seed admin if empty
seed_admin()

# --- App UI ---
st.set_page_config(page_title="MicroCoils Project Monitoring Tools", layout="wide")
st.title("MicroCoils Project Monitoring Tools")

# Authentication (simple)
if 'auth' not in st.session_state:
    st.session_state.auth = {"logged_in": False, "username": None, "display_name": None, "role": None}

with st.sidebar:
    st.header("Sign In")
    if not st.session_state.auth["logged_in"]:
        uname = st.text_input("Username")
        pwd = st.text_input("Password", type="password")
        if st.button("Sign in"):
            user = get_user(uname)
            if not user:
                st.error("User not found")
            else:
                if check_password_hash(user.password_hash, pwd):
                    st.session_state.auth = {"logged_in": True, "username": user.username, "display_name": user.display_name, "role": user.role}
                    st.success(f"Signed in as {user.display_name}")
                else:
                    st.error("Wrong password")
        if st.button("Reset DB (admin only)"):
            st.warning("Reset is not available here. Use admin functions to manage users/data.")
    else:
        st.write(f"Signed in as **{st.session_state.auth['display_name']}** ({st.session_state.auth['role']})")
        if st.button("Sign out"):
            st.session_state.auth = {"logged_in": False, "username": None, "display_name": None, "role": None}
    st.markdown("---")
    if st.session_state.auth["role"] == "admin":
        st.subheader("Admin: Create user")
        new_u = st.text_input("New username", key="nu1")
        new_dn = st.text_input("Display name", key="nu2")
        new_pw = st.text_input("Password", key="nu3")
        new_role = st.selectbox("Role", ["user","admin"], key="nu4")
        if st.button("Create user"):
            ok = create_user(new_u, new_dn or new_u, new_pw, role=new_role)
            if ok:
                st.success("User created")
            else:
                st.error("User exists")

# main content: require sign in
if not st.session_state.auth["logged_in"]:
    st.info("Please sign in (default admin: admin / Micro@123 if first run). Admin can create users.")
    st.stop()

# --- Data entry tabs ---
tab1, tab2, tab3, tab4 = st.tabs(["Projects", "Tasks", "Issues", "Dashboard"])

# Projects tab
with tab1:
    st.subheader("Add / Edit Project")
    col1, col2 = st.columns(2)
    with col1:
        code = st.text_input("Project Code")
        name = st.text_input("Project Name")
    with col2:
        sdate = st.date_input("Baseline Start", value=date.today())
        edate = st.date_input("Baseline End", value=date.today())
    if st.button("Save Project"):
        # upsert
        existing = db.execute(projects_tbl.select().where(projects_tbl.c.code==code)).first()
        if existing:
            db.execute(projects_tbl.update().where(projects_tbl.c.code==code).values(name=name, baseline_start=sdate, baseline_end=edate))
        else:
            db.execute(projects_tbl.insert().values(code=code, name=name, baseline_start=sdate, baseline_end=edate))
        db.commit()
        st.success("Saved")
    proj_df = pd.DataFrame(db.execute(projects_tbl.select()).fetchall())
    if not proj_df.empty:
        st.dataframe(proj_df)

# Tasks tab
with tab2:
    st.subheader("Add Task")
    projects_list = [r.code for r in db.execute(projects_tbl.select()).fetchall()]
    proj_sel = st.selectbox("Project Code", options=[""] + projects_list)
    ttitle = st.text_input("Title")
    pstart = st.date_input("Planned Start", value=date.today())
    pend = st.date_input("Planned End", value=date.today())
    owner = st.text_input("Owner", value=st.session_state.auth["display_name"])
    status = st.selectbox("Status", ["NotStarted","InProgress","Blocked","Complete"])
    pct = st.number_input("% Complete", min_value=0, max_value=100, value=0)
    if st.button("Save Task"):
        db.execute(tasks_tbl.insert().values(project_code=proj_sel, title=ttitle, planned_start=pstart, planned_end=pend, actual_end=None, percent_complete=pct, status=status, owner=owner))
        db.commit()
        st.success("Task saved")
    tasks_df = pd.DataFrame(db.execute(tasks_tbl.select()).fetchall())
    if not tasks_df.empty:
        st.dataframe(tasks_df)

# Issues tab
with tab3:
    st.subheader("Add Issue / Blocker")
    issue_proj = st.selectbox("Project", options=[""] + projects_list)
    issue_taskid = st.text_input("Task ID (optional)")
    ititle = st.text_input("Title")
    cause = st.text_input("Cause Category")
    iowner = st.text_input("Owner", value=st.session_state.auth["display_name"])
    sev = st.selectbox("Severity", ["Low","Medium","High","Critical"])
    istatus = st.selectbox("Status", ["Open","InProgress","Resolved","Closed"])
    if st.button("Save Issue"):
        db.execute(issues_tbl.insert().values(project_code=issue_proj, task_id=issue_taskid or None, title=ititle, cause=cause, owner=iowner, severity=sev, status=istatus))
        db.commit()
        st.success("Issue saved")
    issues_df = pd.DataFrame(db.execute(issues_tbl.select()).fetchall())
    if not issues_df.empty:
        st.dataframe(issues_df)

# Dashboard
with tab4:
    st.subheader("Single-View Dashboard")
    df_tasks = pd.DataFrame(db.execute(tasks_tbl.select()).fetchall())
    df_issues = pd.DataFrame(db.execute(issues_tbl.select()).fetchall())

    # KPIs
    total_projects = db.execute(projects_tbl.count()).scalar()
    total_tasks = len(df_tasks)
    tasks_completed = len(df_tasks[df_tasks['percent_complete'] >= 100]) if not df_tasks.empty else 0
    overdue = 0
    on_time_pct = 0
    avg_variance = 0
    if not df_tasks.empty:
        df_tasks['planned_end'] = pd.to_datetime(df_tasks['planned_end'])
        df_tasks['actual_end'] = pd.to_datetime(df_tasks['actual_end'], errors='coerce')
        overdue = df_tasks[(df_tasks['actual_end'].isna()) & (df_tasks['planned_end'] < pd.Timestamp.today())].shape[0]
        completed = df_tasks[df_tasks['actual_end'].notna()]
        if not completed.empty:
            on_time = completed[completed['actual_end'] <= completed['planned_end']].shape[0]
            on_time_pct = round(100 * on_time / completed.shape[0], 1)
            completed['variance'] = (completed['actual_end'] - completed['planned_end']).dt.days
            avg_variance = round(completed['variance'].mean(), 1)

    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("Total Projects", total_projects)
    c2.metric("Total Tasks", total_tasks)
    c3.metric("Tasks Completed", tasks_completed)
    c4.metric("Tasks Overdue", overdue)
    c5.metric("% Tasks On Time", f"{on_time_pct}%")
    c6.metric("Avg Schedule Variance (days)", avg_variance)

    # Top causes
    if not df_issues.empty:
        fig1 = px.bar(df_issues['cause'].value_counts().reset_index().rename(columns={'index':'cause','cause':'count'}), x='cause', y='count', title='Top Delay Causes')
        st.plotly_chart(fig1, use_container_width=True)
    # Owner overdue
    if not df_tasks.empty:
        owners = df_tasks[(df_tasks['actual_end'].isna()) & (df_tasks['planned_end'] < pd.Timestamp.today())]['owner'].value_counts().reset_index().rename(columns={'index':'owner','owner':'overdue'})
        if not owners.empty:
            fig2 = px.bar(owners, x='owner', y='overdue', title='Overdue Tasks by Owner')
            st.plotly_chart(fig2, use_container_width=True)

    # CSV export
    if st.button("Export Dashboard CSV"):
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["KPI","Value"])
        writer.writerow(["Total Projects", total_projects])
        writer.writerow(["Total Tasks", total_tasks])
        writer.writerow(["Tasks Completed", tasks_completed])
        writer.writerow(["Tasks Overdue", overdue])
        writer.writerow(["% Tasks On Time", on_time_pct])
        st.download_button("Download summary CSV", data=buf.getvalue(), file_name="dashboard_summary.csv")
