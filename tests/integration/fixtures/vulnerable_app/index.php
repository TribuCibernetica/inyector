<?php
// Objetivo deliberadamente vulnerable para tests de integración:
// concatenación cruda + error MySQL visible, el mismo patrón que
// testphp.vulnweb.com. Sirve para verificar que inyector detecta una
// SQLi real de punta a punta (recon -> sqlmap -> reporte).
$conn = mysqli_connect("test_db", "root", "root", "testdb");

$id = isset($_GET['id']) ? $_GET['id'] : '1';
$query = "SELECT * FROM products WHERE id = " . $id;
$result = mysqli_query($conn, $query);

echo "<html><body>";
echo "<h2>Product listing</h2>";

if (!$result) {
    echo "<p style='color:red'>Error: " . mysqli_error($conn) . "</p>";
} else {
    while ($row = mysqli_fetch_assoc($result)) {
        echo "<p>" . $row['id'] . " - " . $row['name'] . "</p>";
    }
}
echo "</body></html>";
