"""
Unit Tests for AgentGuard Sandboxed Tools & Virtual Environment
"""
import pytest
from app.agent.tools import (
    VirtualFileSystem,
    VirtualSandbox,
    ToolRegistry,
    ReadFileTool,
    WriteFileTool,
    DeleteFileTool,
    RunCommandTool,
    NetworkRequestTool,
    InstallPackageTool,
    ListDirectoryTool,
)
from app.core.models import ActionType


@pytest.fixture
def sandbox():
    return VirtualSandbox()


def test_virtual_fs_read_existing_file(sandbox):
    tool = ReadFileTool()
    res = tool.execute(sandbox, "./project/main.py", {})
    assert res.success is True
    assert "def main():" in res.output


def test_virtual_fs_read_missing_file(sandbox):
    tool = ReadFileTool()
    res = tool.execute(sandbox, "./nonexistent_file.txt", {})
    assert res.success is False
    assert "not found" in res.error.lower()


def test_virtual_fs_write_and_read_back(sandbox):
    write_tool = WriteFileTool()
    read_tool = ReadFileTool()
    
    write_res = write_tool.execute(sandbox, "./project/test.py", {"content": "print('test')"})
    assert write_res.success is True
    
    read_res = read_tool.execute(sandbox, "./project/test.py", {})
    assert read_res.success is True
    assert read_res.output == "print('test')"


def test_virtual_fs_delete_file(sandbox):
    write_tool = WriteFileTool()
    delete_tool = DeleteFileTool()
    read_tool = ReadFileTool()

    write_tool.execute(sandbox, "./temp.txt", {"content": "temp data"})
    del_res = delete_tool.execute(sandbox, "./temp.txt", {})
    assert del_res.success is True

    read_res = read_tool.execute(sandbox, "./temp.txt", {})
    assert read_res.success is False


def test_run_command_tool(sandbox):
    tool = RunCommandTool()
    res = tool.execute(sandbox, "pytest", {})
    assert res.success is True
    assert "passed" in res.output


def test_network_request_tool(sandbox):
    tool = NetworkRequestTool()
    res = tool.execute(sandbox, "https://api.example.com/data", {"method": "POST", "data": {"key": "val"}})
    assert res.success is True
    assert res.output["status_code"] == 200
    assert res.output["method"] == "POST"


def test_install_package_tool(sandbox):
    tool = InstallPackageTool()
    res = tool.execute(sandbox, "requests-mock", {})
    assert res.success is True
    assert "Successfully installed requests-mock" in res.output
    assert "requests-mock" in sandbox.installed_packages


def test_list_directory_tool(sandbox):
    tool = ListDirectoryTool()
    res = tool.execute(sandbox, "./project", {})
    assert res.success is True
    assert isinstance(res.output, list)
    assert any("./project/main.py" in f for f in res.output)


def test_tool_registry_has_all_7_tools():
    registry = ToolRegistry()
    assert registry.get_tool(ActionType.READ_FILE) is not None
    assert registry.get_tool(ActionType.WRITE_FILE) is not None
    assert registry.get_tool(ActionType.DELETE_FILE) is not None
    assert registry.get_tool(ActionType.RUN_COMMAND) is not None
    assert registry.get_tool(ActionType.NETWORK_REQUEST) is not None
    assert registry.get_tool(ActionType.INSTALL_PACKAGE) is not None
    assert registry.get_tool(ActionType.LIST_DIRECTORY) is not None
    assert len(registry.list_tools()) == 7
