"""Tests para EndpointMapper — en particular que injectable_params
realmente priorice parámetros con nombres típicos de SQLi ('id', etc)
y que los valores de POST se decodifiquen igual que los de GET."""

from inyector.recon.endpoint_mapper import EndpointMapper


def test_get_params_prioritizes_known_high_value_names():
    mapper = EndpointMapper()
    result = mapper.map_parameters("http://example.com/page.php?ref=abc&id=42")

    top = result["injectable_params"][0]
    assert top["name"] == "id"
    assert top["priority"] == "alta"


def test_post_data_is_url_decoded_like_get_params():
    mapper = EndpointMapper()
    result = mapper.map_parameters(
        "http://example.com/search",
        method="POST",
        data="query=John+Smith&cat=1%2F2",
    )
    assert result["params_post"]["query"] == "John Smith"
    assert result["params_post"]["cat"] == "1/2"


def test_total_params_counts_get_and_post():
    mapper = EndpointMapper()
    result = mapper.map_parameters(
        "http://example.com/x?a=1&b=2", method="POST", data="c=3",
    )
    assert result["total_params"] == 3
