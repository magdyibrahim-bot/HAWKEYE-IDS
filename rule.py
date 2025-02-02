import json

class Rule:
    def __init__(self, rule_dict):
        self.action = rule_dict["action"]
        self.protocol = rule_dict["protocol"]
        self.src_ip = rule_dict["src_ip"]
        self.dst_ip = rule_dict["dst_ip"]
        self.src_port = rule_dict["src_port"]
        self.dst_port = rule_dict["dst_port"]
        self.options = rule_dict.get("options", {})
    
    def get_rules_from_db(conn):
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM rules")
        rows = cursor.fetchall()
    
        rules = []
        for row in rows:
            rules.append({
                "id": row[0],
                "action": row[1],
                "protocol": row[2],
                "src_ip": row[3],
                "src_port": row[4],
                "direction": row[5],
                "dst_ip": row[6],
                "dst_port": row[7],
                "options": json.loads(row[8]) 
            })
        
        return rules

    def matches(self, packet):
        
        if self.protocol != "any" and packet.get_key("protocol") != self.protocol:
            return False
        
        if self.src_ip != "any" and packet.get_key("src_ip") != self.src_ip:
            return False
        
        if self.dst_ip != "any" and packet.get_key("dst_ip") != self.dst_ip:
            return False
        
        if self.src_port != "any" and packet.get_key("src_port") != self.src_port:
            return False

        if self.dst_port != "any" and packet.get_key("dst_port") != self.dst_port:
            return False

        return True


    def __str__(self):   
         
        rule_info = {
            "protocol": self.protocol,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "options":self.options
        }
        
        return str(rule_info)