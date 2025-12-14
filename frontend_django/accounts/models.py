from django.db import models


class AuditLog(models.Model):
    user_id = models.IntegerField(null=True, blank=True)
    action = models.CharField(max_length=100)
    ip_address = models.CharField(max_length=45, null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "audit_log"
        managed = True
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["-created_at"], name="audit_created_idx"),
            models.Index(fields=["user_id", "-created_at"], name="audit_user_created_idx"),
            models.Index(fields=["action"], name="audit_action_idx"),
        ]

    def __str__(self) -> str:
        return f"[{self.created_at}] user={self.user_id} action={self.action}"
