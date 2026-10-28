"""Strict evidence tests for QEMU software-only GPU queue and fences."""
import unittest
from qemu_gpu_sw_queue_smoke import validate,MARKER
from test_qemu_vbe_mode_rollback_smoke import GOOD as BASE_GOOD

GOOD=BASE_GOOD.replace("WOLFOS_FB_TEXT_OK",MARKER+"\nWOLFOS_FB_TEXT_OK")

class GpuSoftwareQueueEvidenceTests(unittest.TestCase):
    def test_realistic_success(self):
        self.assertTrue(validate(GOOD,33))
    def test_no_marker(self):
        self.assertFalse(validate(BASE_GOOD,33))
    def test_duplicate_marker(self):
        self.assertFalse(validate(GOOD+MARKER+"\n",33))
    def test_extra_fake_marker(self):
        self.assertFalse(validate(GOOD+"WOLFOS_GPU_SW_QUEUE_OK bogus\n",33))
    def test_wrong_exit(self):
        self.assertFalse(validate(GOOD,0))
    def test_wrong_gpu_identifier(self):
        self.assertFalse(validate(GOOD.replace("SW_QUEUE_OK pci=1234:1111","SW_QUEUE_OK pci=10de:2684"),33))
    def test_software_is_not_native_acceleration(self):
        self.assertFalse(validate(GOOD.replace(MARKER,MARKER.replace("native_accel=0","native_accel=1")),33))
    def test_exact_pitch_required(self):
        self.assertFalse(validate(GOOD.replace("size=1280x800 pitch=5120","size=1280x800 pitch=4096"),33))
    def test_two_batches_are_required(self):
        self.assertFalse(validate(GOOD.replace("submissions=2 commands=4","submissions=1 commands=4"),33))
    def test_exact_command_count_required(self):
        self.assertFalse(validate(GOOD.replace("commands=4","commands=3"),33))
    def test_completed_fence_two_required(self):
        self.assertFalse(validate(GOOD.replace("last_fence=2","last_fence=1"),33))
    def test_overlapping_copy_evidence_required(self):
        self.assertFalse(validate(GOOD.replace("overlap_copy=1","overlap_copy=0"),33))
    def test_untouched_pixel_evidence_required(self):
        self.assertFalse(validate(GOOD.replace("untouched_pixel=1","untouched_pixel=0"),33))
    def test_pixel_restoration_evidence_required(self):
        self.assertFalse(validate(GOOD.replace("pixels_restored=1","pixels_restored=0"),33))
    def test_queue_failure_invalidates_success(self):
        self.assertFalse(validate(GOOD+"WOLFOS_GPU_SW_QUEUE_FAIL stage=execute\n",33))
    def test_explicit_test_failure_invalidates_success(self):
        self.assertFalse(validate(GOOD+"WOLFOS_GPU_SW_QUEUE_TEST_FAILED\n",33))
    def test_native_driver_claim_forbidden(self):
        self.assertFalse(validate(GOOD+"WOLFOS_GPU_DRIVER_LOADED\n",33))
    def test_no_success_before_hardware_rollback(self):
        rows=GOOD.splitlines()
        a=next(i for i,r in enumerate(rows) if r.startswith("WOLFOS_GPU_SW_QUEUE_OK"))
        b=next(i for i,r in enumerate(rows) if r.startswith("WOLFOS_QEMU_VBE_MODE_ROLLBACK_OK"))
        rows[a],rows[b]=rows[b],rows[a]
        self.assertFalse(validate("\n".join(rows)+"\n",33))
    def test_no_success_after_framebuffer_text(self):
        rows=GOOD.splitlines()
        a=next(i for i,r in enumerate(rows) if r.startswith("WOLFOS_GPU_SW_QUEUE_OK"))
        b=next(i for i,r in enumerate(rows) if r.startswith("WOLFOS_FB_TEXT_OK"))
        rows[a],rows[b]=rows[b],rows[a]
        self.assertFalse(validate("\n".join(rows)+"\n",33))
    def test_previous_bochs_proof_still_required(self):
        self.assertFalse(validate(GOOD.replace("WOLFOS_QEMU_VBE_MODE_ROLLBACK_OK",
                                               "NO_QEMU_ROLLBACK"),33))
    def test_exact_marker_only(self):
        self.assertFalse(validate(GOOD.replace(MARKER,MARKER+" extra=true"),33))
if __name__=="__main__":
    unittest.main()
