import pytest

from app_args import parse_int_list


@pytest.mark.unit
def test_parse_int_list_empty():
    assert sorted(parse_int_list("")) == []


@pytest.mark.unit
def test_parse_int_list_full_range():
    result = sorted(parse_int_list("-"))
    assert len(result) == 65535
    assert result[0] == 1
    assert result[-1] == 65535


@pytest.mark.unit
def test_parse_int_list_all():
    result = sorted(parse_int_list("0-65535"))
    assert len(result) == 65536
    assert result[0] == 0
    assert result[-1] == 65535


@pytest.mark.unit
def test_parse_int_list_single_port():
    assert sorted(parse_int_list("22")) == [22]


@pytest.mark.unit
def test_parse_int_list_comma_separated():
    assert sorted(parse_int_list("80,443,8080")) == [80, 443, 8080]


@pytest.mark.unit
def test_parse_int_remove_duplicates():
    assert sorted(parse_int_list("80,443,8080,80,443")) == [80, 443, 8080]


@pytest.mark.unit
def test_parse_int_list_range():
    result = sorted(parse_int_list("20-1000"))
    assert len(result) == 981  # Should be 981 if inclusive
    assert 20 in result
    assert 999 in result
    assert 1000 in result
    assert 1001 not in result


@pytest.mark.unit
def test_parse_int_list_complex():
    result = sorted(parse_int_list("22,80-83,90"))
    assert result == [22, 80, 81, 82, 83, 90]


@pytest.mark.unit
def test_parse_int_list_with_spaces():
    assert sorted(parse_int_list(" 22 , 80 ")) == [22, 80]


@pytest.mark.unit
def test_parse_int_list_invalid_port_negative():
    with pytest.raises(ValueError):
        sorted(parse_int_list("-1"))


@pytest.mark.unit
def test_parse_int_list_invalid_port_too_large():
    with pytest.raises(ValueError):
        sorted(parse_int_list("65536"))
