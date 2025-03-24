from angr.procedures.stubs.format_parser import FormatParser
from angr.storage.file import SimFileDescriptorDuplex
from cle.backends.externs.simdata.io_file import io_file_data_for_arch

class myfprintf(FormatParser):
    def run(self, file_ptr, fmt):  # pylint:disable=unused-argument
        fd_offset = io_file_data_for_arch(self.state.arch)["fd"]
        
        # Check if file_ptr is a SimFileDescriptorDuplex
        if isinstance(file_ptr, SimFileDescriptorDuplex):
            fileno = file_ptr.fd  # Extract file descriptor as an integer
        else:
            fileno = self.state.mem[file_ptr + fd_offset:].int.resolved  # Default case

        simfd = self.state.posix.get_fd(fileno)
        if simfd is None:
            return -1

        # The format str is at index 1
        fmt_str = self._parse(fmt)
        out_str = fmt_str.replace(self.va_arg)

        simfd.write_data(out_str, out_str.size() // 8)

        return out_str.size() // 8