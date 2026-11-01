// Hardened version of examples/vulnerable/OrderRepository.cs.
using System.Data.SqlClient;

public class OrderRepository {

    public SqlDataReader FindOrder(string id) {
        // Parameterized SqlCommand: no string concatenation at all.
        var cmd = new SqlCommand("SELECT * FROM orders WHERE id = @id");
        cmd.Parameters.AddWithValue("@id", id);
        return cmd.ExecuteReader();
    }
}
