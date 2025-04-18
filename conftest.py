import pytest


def pytest_itemcollected(item):
    """Add docstrings to test names in the HTML report"""
    if item.obj.__doc__:
        item._nodeid = f"{item.obj.__doc__.strip()}"


def pytest_html_results_table_header(cells):
    del cells[3]


#     cells.insert(2, "<th>Description</th>")
#     cells.insert(1, '<th class="sortable time" data-column-type="time">Time</th>')
#
#
def pytest_html_results_table_row(report, cells):
    del cells[3]


#     cells.insert(2, f"<td>{report.description}</td>")
#


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    report.description = str(item.function.__doc__)
