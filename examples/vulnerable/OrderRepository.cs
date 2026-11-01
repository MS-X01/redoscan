// Intentionally vulnerable C#/.NET code for demo and CI purposes.
// See examples/safe/OrderRepository.cs for the corrected version.
using System.Data.SqlClient;

public class OrderRepository {

    public SqlDataReader FindOrder(string id) {
        // CWE-89: SqlCommand built by concatenating a query string
        var cmd = new SqlCommand("SELECT * FROM orders WHERE id = " + id);
        return cmd.ExecuteReader();
    }
}
